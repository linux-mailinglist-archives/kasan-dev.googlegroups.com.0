Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE6RVWBAMGQELPXZWKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 627C9338E65
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 14:11:48 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id q16sf7218445vkq.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 05:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615554707; cv=pass;
        d=google.com; s=arc-20160816;
        b=u53vzu+lcGPusktOnTIM9Dbb/CON5YSOQi6MVH61g6yos1K6TW7p95LVigO6CFfARj
         FpYespRAX33ySQw2Wp6u5IWSNlE13eLge2chRiLJ5d+Rj/dgvPzxJim0qtIipl133Nsc
         hwPeVuCHXeBS7DMwbtN0vQOhVDtl/RglCZS4jg+hUWgVP3GDMr0K8JTAZSXcr+IkMA2V
         yM6xTaCWpJOnSPykE1bE0X2LTrKNdsmizNn8gkURFVZCHAQBRnT+ztsaANSNdLOQHNr+
         KepgcLw2xMK0PrY9hts2e5uCQ9NvjKoZAqCOuAT6/PuVbWE47d+xtZpff1hZ3MGvU1jE
         5Juw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8/kUuDMxYlHWT+XGnx7VRNlzd378mQKKIBQ3P50EeLs=;
        b=Zl7s9zjefOyZxN2Tu1FcIN0e56CmxbBnvY76sYI0Z8db0LMBKeIsjxW9F95tIGdLLZ
         djfr63T70zEFrqebiUwSZlKLbBpwfRvn1wzpvRvqzlGvJY2G+wXo63b+aRo0QaNKdz9t
         M6CM7tdwsxBpzOWp3zeU9JgMR71RCyI0duhgxTIGNJ2hAcxRe2OikV+r5nXia1pH7r5J
         tCOcxXuv8u3A/sIPgLoH4y4/kffTHDUjz7BRwjq99pfDiSYXoG6MQARyyvJWiRzQatBK
         jVgeqM8w6WBIyYdtvi1vzL9aajMVfLOMfLsaSyZn8evaW0hHJw7MMGTb1woNXqGPVjbs
         BzJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZsvLdjz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8/kUuDMxYlHWT+XGnx7VRNlzd378mQKKIBQ3P50EeLs=;
        b=fCWUwT5gpFQm6dChI4A13NR/mqnxC0UnYQtyv1ROJclicK4mhGTuXBNt65c3w5LoO/
         RSix6vxxa0Tzx4PcPCkmBcp3mErDTmb8Q4rPBcZZ0Dt8sODhDGdZxKQu3DmtZJVXOZrr
         nFjx+PUYvDGgClTwx3/6OId1jjH2vSVLUih62p82+v+quTECGR1XJ9Yjw3yfz8IiejDt
         g08maNmaa9Zb44ajOOWpW4cxfuKHottXFjz9nt9BgiUf245u/NGGoBwY91a5bU5m4wCk
         1yoPYXv3l/gvbnuJX2sqFBUwR10SZnw8i1ESg2Gl/2F3rXMaTfzKcw4vlonOgw/oIrgb
         R+dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8/kUuDMxYlHWT+XGnx7VRNlzd378mQKKIBQ3P50EeLs=;
        b=Sh8H8R64FbI9JIIzBgkn0IxyRp9e6Ka0cwEAtitRF6mL3SnAQZy5KdH0GS4mi2sDj+
         gsklUTz7ladoVUltg/ef3cpOswI+unopCcr9gQ12kIOzJLSblGFCG63M6Cy66W/hjjC5
         yiL1mCNlGFC2mzL7F6eJ86KcIRn+5qY+3vwNHPVpU/vbF7YKSfQzYCpeYaMrEggGGtl0
         wvcA0xcUf3y6YlrA54gu2KJKSQZF6oBagBh+Pu7o29+3pslE8JJkWFZuu7mfPVkgNXJd
         a8MsazZEspYsix+8NAmSSko7jnXNHipmCNYx1WeqyTyaav8NKCyPtdYPAqL8F1ffjmD2
         JIGQ==
X-Gm-Message-State: AOAM530qt1ylOz30tAr9V8C1S0jXlrlEICWQgciNYGpLI7KQFAp2INaU
	PTSmAMHyIrkoTNn6F06eEOw=
X-Google-Smtp-Source: ABdhPJwQEBhQr9vEa/cOd7JdvmD/qtY80N8dXX0142LNbW6XbL9zSotE/4jUgKE//3/EbcyzI9ss+g==
X-Received: by 2002:a67:d99c:: with SMTP id u28mr7530218vsj.53.1615554707519;
        Fri, 12 Mar 2021 05:11:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:94c6:: with SMTP id w189ls480594vkd.0.gmail; Fri, 12 Mar
 2021 05:11:47 -0800 (PST)
X-Received: by 2002:a1f:7846:: with SMTP id t67mr7813781vkc.21.1615554706957;
        Fri, 12 Mar 2021 05:11:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615554706; cv=none;
        d=google.com; s=arc-20160816;
        b=WFHP7fJCfFuFsznu+cSABkUMGo7pT9rhL7govFnhfhTOsFQpWTQ+vjoT708b9LLfbe
         GjpIV3x7IgCCOfHNjwXt/gSDDngJMk6Q/Bpq8xX8XAEPKhGrULrYiu4qBnlFDnXqg+4Q
         IZHB/BFBlJNWrwGMbUDGyxLPw6b2w/8eipglEu6aUtfO/uLW1VmAeUHGDMTJp82rfSjE
         0H91ar1f6nM+HzIsByQdxIQ7MZ1UKur/a+4inGa38rFQPYBqRAmqg6RMCyril5uB/3QD
         hrNpjVJ51dbUEnFl/KwtA8KooT5Pu+ZMHeQeInhBMm4ArXwQPbSOslUHMsyuNDIZAI9x
         xnmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iwzo0YXF8Wjs0+r/brLS8Xn8OgIC+M4fxdQ/Xk6iPEU=;
        b=VDEzpdQLyRFfGnOUQ4pzX9At9wzNOad56EJkCHNEdXwdDa6CrtdTSFtzdvmlFT8dOM
         bxMWwZXCvT3AqsQbbR14wYEBp01Gov3M6ANZvMW1pQQW+MWezkTG81yDOV8uXz+Domkr
         TqG6y2gIJ44Oq5Y2lgUgTppmd5a7vHCDLU4bTa7I5VyRzUHB+aWfBJ8Uuxm5SUuyrf1k
         ST59QRcZEv4xeqH0sxaGc2kRdD0TmDTeVP/qGwH//i5F7B7c/sn4bxoZDAV2tOGJz5Gz
         7NXZejQ0p+wm3ggpQyuzFR3cV+4SbOowcclhAc4k796GquGlXljw0/IweVjM5ksGxQMT
         kGNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZsvLdjz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id r5si280609vka.3.2021.03.12.05.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 05:11:46 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id b130so24087975qkc.10
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 05:11:46 -0800 (PST)
X-Received: by 2002:a37:630a:: with SMTP id x10mr12286451qkb.326.1615554706426;
 Fri, 12 Mar 2021 05:11:46 -0800 (PST)
MIME-Version: 1.0
References: <20210312121653.348518-1-elver@google.com>
In-Reply-To: <20210312121653.348518-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 14:11:35 +0100
Message-ID: <CAG_fn=WdpzPxbvzqkpVXjyrUu=GprA2xMBiJdhJqM8cNhABWmw@mail.gmail.com>
Subject: Re: [PATCH mm] kfence: zero guard page after out-of-bounds access
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FZsvLdjz;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
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

On Fri, Mar 12, 2021 at 1:16 PM Marco Elver <elver@google.com> wrote:
>
> After an out-of-bounds accesses, zero the guard page before
> re-protecting in kfence_guarded_free(). On one hand this helps make the
> failure mode of subsequent out-of-bounds accesses more deterministic,
> but could also prevent certain information leaks.
>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
>  mm/kfence/core.c | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 3b8ec938470a..f7106f28443d 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -371,6 +371,7 @@ static void kfence_guarded_free(void *addr, struct kf=
ence_metadata *meta, bool z
>
>         /* Restore page protection if there was an OOB access. */
>         if (meta->unprotected_page) {
> +               memzero_explicit((void *)ALIGN_DOWN(meta->unprotected_pag=
e, PAGE_SIZE), PAGE_SIZE);
>                 kfence_protect(meta->unprotected_page);
>                 meta->unprotected_page =3D 0;
>         }
> --
> 2.31.0.rc2.261.g7f71774620-goog
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
kasan-dev/CAG_fn%3DWdpzPxbvzqkpVXjyrUu%3DGprA2xMBiJdhJqM8cNhABWmw%40mail.gm=
ail.com.
