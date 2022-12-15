Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3U35WOAMGQECSZRTSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id E894564DECD
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 17:40:15 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id b4-20020a253404000000b006fad1bb09f4sf4426334yba.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Dec 2022 08:40:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671122415; cv=pass;
        d=google.com; s=arc-20160816;
        b=gZ7B8Qj1IVZmX0VHvugXy7Edyom97w/k1oP5epWeuOqZWNp4DF/o6valygo2Styy/c
         DW5d8bcSJYKy9fWLUcMYHxlf94pCBaLNKsLEidzn9Dea59pliOIyJD4FJoggMHs9xO8g
         NzMkoFgvanfZODh6NVpOdu7b7c3o+gBsA9ws/zGWM/SiIc/1dzIHI6iT/hDT3DQsV7eJ
         le7iTrWc9XUozxMT/uSHz5ORyBx+gkrKApUzjX2NLyCnl7L4w/8T+d6GIQ+flzp/zbhM
         /Pa3IV5FqTFpJRX/N0UF1GhUO2Bhi/zY2aviTjjOaSUWYtOtb+cbjlT29I0mwJJfKXGC
         YuBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AQuOli+9lqoJD2zDdtbWrmXjS+BA0HvZhde7qTrKBsc=;
        b=iMa6J8hOdPGq4lF5Sz+30bTPiaB29Gx88hjD19xHLlYmGXLCuB3Iqf87aF1wan5gWe
         E6OslWIuEovc4pO3Ue5nJ86On+R+P8VWVuXQ531uuxqIxKFSyF8GQs+KjLyP7De0Sw+S
         cThD+LOcIx+BGQhwCiPsFmKnOPtlgQZjMBGLuMAzv4seDuewBr2wDyMhcBXG6G/Muqon
         G6rMx9QAJGn3RGwQcYBCEF1y6y450TcdFsUe5irPRXzEIRZZWxr0Qs8Z990qvgl0AZeN
         iocj317D+YRpgbRD0e7mlv2us7roXdv88go9UQsZrFWlApmjbPahD3LHtqwrYJIrDJlq
         Eovg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QKXMNonQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AQuOli+9lqoJD2zDdtbWrmXjS+BA0HvZhde7qTrKBsc=;
        b=eNCzEMRfZQB5yn8QtctocSSS6B6IIwO1EKwkYFExYYYi9SoYIOU6AepxXpyq5BTgfe
         iXFtGfDn9u6mOGgCzZc1KGFkop6kbFgbdvftQjbBm8nu8jx4WD/78owZ0vg9FwVUNdJ6
         8HRnXgW5vdAXttlAHvQanSbuAkfcKYcN3shOnWFLrSF+ko3bH6CzOGyTXUmUvYd8MsTq
         A48C1EE1sDrp+lSrhE45ByPaVQo+z0TNWIG3EpX1kDeS2znaLT+QRYGFpqNwSzspIyt5
         uwaZJCDwi2GUMDb8+Rqu3PZS8I3EiSrvsIBm/otsIKqhjyrLxV5qeSu9YpPkYLrtHI8M
         CwlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AQuOli+9lqoJD2zDdtbWrmXjS+BA0HvZhde7qTrKBsc=;
        b=MZL9DEbuF5RCHelvtZlSTTb6ytU5540xQXyDKJ8+xj/bNcXGIXGPLIkuahS4JuG/Yz
         vYQIB7DnAw5YJos6dofXXsj7cGStt/To4m6vMXVfx4QodjaIge5ZJkltoiLu3zG9Ng/w
         DZnBIv0Mee4SDsQ1c6j+c8Ui+ZGn/gHnEYJFqcAnapxAZ1YbfiLOEVjBDRys/XwcsRk9
         TpPqgGJYiTC78oYmi+/k+6ju1HjdZD8YgD/5WS0IrvEY3Bsmw6oia+zdXmVVr7chDNaW
         PRVQbawlq9IprEWlWccMdQX3QPaxsvbbBfWSnKuoR2R6vDm1OcIklHKMTnpW9/IsC8lh
         ZvQg==
X-Gm-Message-State: ANoB5pnZ0utYK5+EK35BK/BnolweeoD4aOx2ld7wHM5a7uHUcyrmIgAQ
	AIw/9kjFrou6+T9Kn1D+KU4=
X-Google-Smtp-Source: AA0mqf6RNDYC0NVwWLElJIXZOhOljqNyKKr82a3vuToPJn7MIJ3MF8bmAfgYmVbZN6OcxmOegJ5lcA==
X-Received: by 2002:a05:690c:b18:b0:3f4:6ecb:471d with SMTP id cj24-20020a05690c0b1800b003f46ecb471dmr14901563ywb.231.1671122414786;
        Thu, 15 Dec 2022 08:40:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cc05:0:b0:3c8:b520:2fde with SMTP id o5-20020a0dcc05000000b003c8b5202fdels14278772ywd.1.-pod-prod-gmail;
 Thu, 15 Dec 2022 08:40:14 -0800 (PST)
X-Received: by 2002:a0d:d107:0:b0:3ab:d729:3a1 with SMTP id t7-20020a0dd107000000b003abd72903a1mr29837526ywd.3.1671122414209;
        Thu, 15 Dec 2022 08:40:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671122414; cv=none;
        d=google.com; s=arc-20160816;
        b=HO9lWlm5rF6cp/2hFekNYpandVW+EEitOql4KDaGC+AKXrvefMulHIF0yRh+YB4Swg
         SMn7OOQkllyVJOma6YYtYOy0lbXcliNbHqeqfljSVLDXHb1JecNRVWKL9YtY9dox8Hia
         J3MjDyFond3WM2gpcgV/mClk1e4Y6dufC3YyJugBqPeHenq/gfVhZZ7hVWB1s7UdNh/c
         Bpq1zLJCb+6fVWtJl8f/Pcy5d4T9IoDPU8MXG2ZaWX+bR2kNjbL1CV/KD46YTJu7Uu74
         e+GH9h6WWzpQhRjF54M5+ei7kxxQplccxbFjls6WvcAy7pqU//nLtlOqprR8kOh6SpKX
         AZjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JBOt4KcrarpWydqrKFp23ubFDXFtAbXyQ+q3FgCY+PA=;
        b=Q9kzpDsKvV3YJ9Ct/ZnwsWYhT2vz1m5/HCzlYPTHgACsQPyeh3Nns2N+K6HFh5xGE7
         sZ46qTwwBzpT+PLVn1UGog9CfuwgMj/HDFeyTLM2H35pI45EjSCYEmJe9kWer73jdsuy
         lyQMelq07R0tZzkBClFvQVIWWPbJzpk3Z/jgLHz7ivloW5z1mvZRADXIv/a42LxItod6
         9bRtDyhGI429D1UV/HyrB8RzTSBOKLcnof3IH3JybrGBZQXvfUDu0SlH7Kn8ArwrtVDv
         efEk8puRcMSiIDbA3pZGtSTlyNHOvwcoQmyN3BPGhQJbMef4/k3g/f9kMtkJjidClyC+
         BdZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QKXMNonQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id w22-20020a814916000000b003d82e3c1d09si227257ywa.4.2022.12.15.08.40.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Dec 2022 08:40:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-3bf4ade3364so49636277b3.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Dec 2022 08:40:14 -0800 (PST)
X-Received: by 2002:a0d:d40e:0:b0:367:23bc:6087 with SMTP id
 w14-20020a0dd40e000000b0036723bc6087mr28375393ywd.428.1671122413726; Thu, 15
 Dec 2022 08:40:13 -0800 (PST)
MIME-Version: 1.0
References: <20221215163046.4079767-1-arnd@kernel.org>
In-Reply-To: <20221215163046.4079767-1-arnd@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Dec 2022 17:39:37 +0100
Message-ID: <CAG_fn=W6TfkPiv57aFEizsmyA9NLGdPa4_CczrSd8dFsL_xSyQ@mail.gmail.com>
Subject: Re: [PATCH] kmsan: include linux/vmalloc.h
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Arnd Bergmann <arnd@arndb.de>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QKXMNonQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Dec 15, 2022 at 5:30 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> This is needed for the vmap/vunmap declarations:
>
> mm/kmsan/kmsan_test.c:316:9: error: implicit declaration of function 'vma=
p' is invalid in C99 [-Werror,-Wimplicit-function-declaration]
>         vbuf =3D vmap(pages, npages, VM_MAP, PAGE_KERNEL);
>                ^
> mm/kmsan/kmsan_test.c:316:29: error: use of undeclared identifier 'VM_MAP=
'
>         vbuf =3D vmap(pages, npages, VM_MAP, PAGE_KERNEL);
>                                    ^
> mm/kmsan/kmsan_test.c:322:3: error: implicit declaration of function 'vun=
map' is invalid in C99 [-Werror,-Wimplicit-function-declaration]
>                 vunmap(vbuf);
>                 ^
>
> Fixes: 8ed691b02ade ("kmsan: add tests for KMSAN")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kmsan/kmsan_test.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index eb44ef3c5f29..088e21a48dc4 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -22,6 +22,7 @@
>  #include <linux/spinlock.h>
>  #include <linux/string.h>
>  #include <linux/tracepoint.h>
> +#include <linux/vmalloc.h>
>  #include <trace/events/printk.h>
>
>  static DEFINE_PER_CPU(int, per_cpu_var);
> --
> 2.35.1
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW6TfkPiv57aFEizsmyA9NLGdPa4_CczrSd8dFsL_xSyQ%40mail.gmai=
l.com.
