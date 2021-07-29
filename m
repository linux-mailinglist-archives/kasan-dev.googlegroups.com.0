Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLGFRKEAMGQE2XNMG2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DAB43DA34B
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 14:44:30 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id w3-20020a0566020343b02905393057ad92sf3764638iou.20
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 05:44:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627562669; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMogufQqIka/T+B/63ls7QVQmKQNHDOO9zJ9CeTkp40wQr3+CYMXcdBLXuGu2emHIp
         1pStnvwKDzT3ThouyO8vHjisfmGzTF0PMVx+MzVm5faV56bomQfF2y9FYE/8Kws4JdnX
         7O3rNFVOz5VQRZOAOz2f0JS2wCqWS+Alnu8mdb+Mqhbz/DmqF/dSy0CiGczms0B1hMN+
         qGfMCfQ7iLpFXqHgMfflEXkHyYwxizol6kR9nP1opa8oDaFDMJaN+XeWfcfj+St6u7xn
         2lGFpV06jev5oXLl3E3l8TNKnqvdu2pGNCXKmYJGFs0BhCn4igz4pQZ01Laf8pygQiVs
         VKdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ghbw/wqFwbvTzB6FMTVKZ1qwsfr0DQwTaQP8XSXB7Fc=;
        b=CgrM9e+pF16UFXRlK2tEfH+ThQr82Dmik9hRaGY52ESjFKcX4pY75awLF5s+b8Ls+L
         RQ8bauuCwwvDcgYAjwn+JEqS8+2/xXmtHIoYctb+8GJ44nGVa9EqKnJwP+kbVWZJ1DLH
         LbS+sNsLww5zAeM65Y2RWeNzRqmviq6esNrN9bYYfNCcvEIyCZvGwvrc9lH2RYUwfHLV
         UMtcP4a8q/hYCE+4gBvyOikro8Uriq7j2QDffMcTHvsnVG1rlKf7+SN1mYffF353V586
         PNLO7xPgJrRjBvdB0TTD4IsYcOHlDPynIs0NcofZl2jhcvylX81kqEpKRuKM2NjIWZ0L
         3FfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BDIdGkUe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ghbw/wqFwbvTzB6FMTVKZ1qwsfr0DQwTaQP8XSXB7Fc=;
        b=o2/XLRRkrHS0JOrYVMBngo5MXbDbnnQYHm8bra/CQ6TT52j1abAll8ep8Wa3buhAMU
         uafgpja7brzbFQGIAAwZBpW+ITdtACgTWc5E76uakGKqm3bPigNXh1vdSAI+DIZ/nSoV
         egZw2wuGX4OfcWCn1tlf/AoqUeWQF1CyxBfqzBRLWAWOblDJuJr+CKx9zyfLYFCiV7VS
         a0LnhiFtfC4+geCInCdejutmJ92aZTiVdZfxokXTCwLq/laO1NyGnt1bef/MzWy1S+4g
         ORa9qQDoT+Mztxfre5IM12a8eIwkwlY9qXABgSk6SiFPBH4naGsfcMvmr3Jats8QLzye
         wvwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ghbw/wqFwbvTzB6FMTVKZ1qwsfr0DQwTaQP8XSXB7Fc=;
        b=TXdrMVfYvz9jJq/uptxxH5tF8K4K8JW+IlHUEz5fQoixHRMgj/zltwezFXEZC3kbQf
         aJ+MYmwanpL4Ejb1ckrqMdFIG2hqZHHrYhYOVHwMXEPdAAl6pq4/b9Vd9TNQas+HYIki
         qmgB2Xm29X3AdGKasggeWCnpJJQeptO3sW86IvneKd0bXYazyHC0DjmcSuScw9QxDeHt
         nepw63Ej24M8sroTfK5g5kk7soUkH5rw8x1CUTTjFL1dYXnqPHxlWSWPSrgzaFUVQPyB
         wxmcwrJCR2zOl5QKb3VDLVjU5qu4GDvzJSK1i8wGSdAHX8HAIzeCe5eR7DHG5JFCqkn+
         sDnw==
X-Gm-Message-State: AOAM532utOl5r/oTWX4Cx9iJu+ufjC8jaJymHRzI1/r0ieX+LUpJe/+9
	Q5GBcuOzhOo5cF6HAOQRdF4=
X-Google-Smtp-Source: ABdhPJzZHlM9vqfD10tzkJWYOa+RDs9yLxixbElWZPD/0ZFzh9XtnIk0iNcb32FZcGeWiq91Q5OzsA==
X-Received: by 2002:a5d:85ca:: with SMTP id e10mr4107543ios.193.1627562668941;
        Thu, 29 Jul 2021 05:44:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:ea0c:: with SMTP id m12ls1012765ioc.2.gmail; Thu, 29 Jul
 2021 05:44:28 -0700 (PDT)
X-Received: by 2002:a5e:9917:: with SMTP id t23mr4135106ioj.158.1627562668576;
        Thu, 29 Jul 2021 05:44:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627562668; cv=none;
        d=google.com; s=arc-20160816;
        b=B59gAvE51WNC/6Lmt6nMPSVwXAUoY31a+N7SezFj7ZzwjFSsxZlLW6fE1WFb25uh65
         nj4xHrKp71RKbiHFsr9yi8XazzRvZeSGdn+njNiKhsZw0I2Q5zXn1nx/pCYwzHN4RWih
         HDp2v4v5VXBaIgdPms8tSOShpTJ0LFEF6HeHlqmHwFX7Z0vzdu4/d027alz1D29z2oLe
         H0pxTC1iA6ZSj4vZTGuTTxYxrWPdgNezh0caVmA9DZtcY1EZ/U3hX3OUcglXOBrOBRth
         cYQZ351xvRHFUDCsSv9B6M4OGJtIylbXyWRxCyY9kfLWOvXC4dv5s+TVLkJ7p1rsN7TJ
         NN6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=REukLMYHB9mfVFO1/bdDCKtlszA1rKroqNl1QPX1pLU=;
        b=ULfIaLnRLi0noNv+FBh5wOb7hq+70nNc6pkukqUJdvBvLQP1YZyNQmuGLswToeva13
         J2t9cg6e6AVw06txmPt4Z341TzWO1CZ2cO/tSwFxm7FstQHrsZvMv8OLNnBorA+GZjba
         tlGxvWxdxNw7xgi5G5IADGaTlmOVJws52D78Wap6QAsmn0QTgtSzNLxtkQ2afJJqIZRL
         CPDcRTeXQwJPnAbgaDjfMPBuUnaah2WKItXfu/L1JgQM9+X1ULXZaBgl1VI5FaVpni0M
         006vYNNf9JSv+XotO/ezL2QlKLUPZqyY+g25E4BlG0uE8S3KxPxIDJ/soTtfdkMiMY10
         QQ3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BDIdGkUe;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id q12si211110iog.2.2021.07.29.05.44.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Jul 2021 05:44:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d9so3778589qty.12
        for <kasan-dev@googlegroups.com>; Thu, 29 Jul 2021 05:44:28 -0700 (PDT)
X-Received: by 2002:a05:622a:10d:: with SMTP id u13mr4063224qtw.369.1627562667841;
 Thu, 29 Jul 2021 05:44:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210728190254.3921642-1-hca@linux.ibm.com> <20210728190254.3921642-3-hca@linux.ibm.com>
In-Reply-To: <20210728190254.3921642-3-hca@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Jul 2021 14:43:51 +0200
Message-ID: <CAG_fn=VS_WFjL+qjm79Jvq5M0KaNScvX2vCw=aNxPx14Hffa0A@mail.gmail.com>
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Sven Schnelle <svens@linux.ibm.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Christian Borntraeger <borntraeger@de.ibm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-s390 <linux-s390@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BDIdGkUe;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jul 28, 2021 at 9:03 PM Heiko Carstens <hca@linux.ibm.com> wrote:
>
> From: Sven Schnelle <svens@linux.ibm.com>
>
> s390 only reports the page address during a translation fault.
> To make the kfence unit tests pass, add a function that might
> be implemented by architectures to mask out address bits.
>
> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
> ---
>  mm/kfence/kfence_test.c | 13 ++++++++++++-
>  1 file changed, 12 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 942cbc16ad26..eb6307c199ea 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -23,8 +23,15 @@
>  #include <linux/tracepoint.h>
>  #include <trace/events/printk.h>
>
> +#include <asm/kfence.h>
> +
>  #include "kfence.h"
>
> +/* May be overridden by <asm/kfence.h>. */
> +#ifndef arch_kfence_test_address
> +#define arch_kfence_test_address(addr) (addr)
> +#endif
> +
>  /* Report as observed from console. */
>  static struct {
>         spinlock_t lock;
> @@ -82,6 +89,7 @@ static const char *get_access_type(const struct expect_=
report *r)
>  /* Check observed report matches information in @r. */
>  static bool report_matches(const struct expect_report *r)
>  {
> +       unsigned long addr =3D (unsigned long)r->addr;
>         bool ret =3D false;
>         unsigned long flags;
>         typeof(observed.lines) expect;
> @@ -131,22 +139,25 @@ static bool report_matches(const struct expect_repo=
rt *r)
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
>                 cur +=3D scnprintf(cur, end - cur, "Out-of-bounds %s at",=
 get_access_type(r));
> +               addr =3D arch_kfence_test_address(addr);

Can we normalize addr once before (or after) this switch?

>                 break;
>         case KFENCE_ERROR_UAF:
>                 cur +=3D scnprintf(cur, end - cur, "Use-after-free %s at"=
, get_access_type(r));
> +               addr =3D arch_kfence_test_address(addr);
>                 break;
>         case KFENCE_ERROR_CORRUPTION:
>                 cur +=3D scnprintf(cur, end - cur, "Corrupted memory at")=
;
>                 break;
>         case KFENCE_ERROR_INVALID:
>                 cur +=3D scnprintf(cur, end - cur, "Invalid %s at", get_a=
ccess_type(r));
> +               addr =3D arch_kfence_test_address(addr);
>                 break;
>         case KFENCE_ERROR_INVALID_FREE:
>                 cur +=3D scnprintf(cur, end - cur, "Invalid free of");
>                 break;
>         }
>
> -       cur +=3D scnprintf(cur, end - cur, " 0x%p", (void *)r->addr);
> +       cur +=3D scnprintf(cur, end - cur, " 0x%p", (void *)addr);
>
>         spin_lock_irqsave(&observed.lock, flags);
>         if (!report_available())
> --
> 2.25.1
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVS_WFjL%2Bqjm79Jvq5M0KaNScvX2vCw%3DaNxPx14Hffa0A%40mail.=
gmail.com.
