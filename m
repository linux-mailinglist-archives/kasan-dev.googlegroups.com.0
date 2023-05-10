Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAUZ5WRAMGQEK5VNXEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id ABA966FD88B
	for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 09:49:23 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-331632be774sf270505605ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 00:49:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683704962; cv=pass;
        d=google.com; s=arc-20160816;
        b=R1u0b0FRGwWCVykwajiD361F7oZVvaVtZhXN8uoMlGSIrWPjDBiazvRu9E5bfj1+rt
         EVvzqSWGl5zqFBmXphpZoPM4IQxMY4ZEaATpur0Os4QBucPYjQuQJi11dmI0+iSZCR6L
         22P6z2LMq74oFXMfGTYGpULPXDcoZczd+xlznsnwbEBPs53CYvK6k/U3SJPN4uWh7BQe
         T4Dfzms0UEbYvON9JLVjVYNL3hESyAOpSpRS5BoKb7lXT9VwLxXRj4TyjAQpp2//bcWd
         jo6DFUltIFbrf1evGXMmLZ6nAnbTu7UkaoF5GOJWt457ENAYqGpYSzla3YZSg2sCPJQX
         Fw0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oy9kWBMyPfME/qkNOS37beNz803pXUX45sFxc67vRkw=;
        b=OVoiSr7hayimwcEhOAC4WJdNZyz/tRe6cSU6Hlt+G4F0eqifXjk1VKrVbmgM3vKma5
         zZW1EFJB/XKMjIDwZlIPLzZ9beM09Bon2oLrG8fA32w++KbY554yXrNK9Fpe5bQsjbTz
         rsovPV//4BOTYmYuqV/OH8EBZL127JrK8hp59+/IzZmXQuRS9qSw9aSmj9fngushcbsl
         C8pmMl4qaetEMpObf6vO9dgwzOXIStsMHpaBr7pfAuX5++NfDGtRxaXHpG8rmlhAvhPr
         V5r3Qn0MAZz3YmXN6ZS0IoEb53DEYPznfMeY06m+Zt/Q9tq1o2DGA2otAIEaSUle5hXk
         bNAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yioaVO9g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683704962; x=1686296962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oy9kWBMyPfME/qkNOS37beNz803pXUX45sFxc67vRkw=;
        b=MnUS7FHZq83pyXoPdBRuMKB8ErkskgtoWpWkj+63yYK5k6sbYHVdYHlgkrxFV1M1Ng
         QNbyvbyZQKP67ryQIWDcp5CJo2siwLNokHFVBzF0NSu077eGWix2DpcnCQCBTCYJjYjD
         RZWmN8xSHSd6Nnt4+zQdV7wQDMVATaUoZHA7T/Xx1G2Urh5xtXJJDmT7C4U8TCBQg+ju
         rq/Xn81eFQc4wugO1L3uAuRIVpzSiNrv6P3xBhdqUL45bRubDBIMLdeu6TWrZ+qjzb9Y
         hZDogjjnHCIB1zJ2ki1WrPEvEmBYLtYmwELd6PyK4WIlPQqlZWeWQ7ft56B/pLU7e+7V
         YpwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683704962; x=1686296962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oy9kWBMyPfME/qkNOS37beNz803pXUX45sFxc67vRkw=;
        b=BST+ABoXMVBsalvUvDOQr83Q32ldH7EFZX/QvpQ6gWeX/8aB0/488JUnf4U9xwotwY
         ktlc8h4YHHN/8z0973M1T3mvl22vDdOwHIinBX4jMWLFZLstzCmtKvCj1Wi+6l3VF+IH
         raPchDnoVjrKoEPKw/G7zDIeBBn96N5yFpyYCEhZdQ+VYFrqMc5eK9VQjO7PXRvkIV/0
         S5XeMLB6WXLYSjXe01nxwuw53/0YttWTyUeA/BYMMu/DisHQJr8C857jR6zqhc8VgdLA
         RjRE2gvRoFb+bkAhOzxGKnYp4Z3/JVwz/gyK/TjYjvxNGdfTwr2IR/gfPlJ9EXAdMmsO
         etKg==
X-Gm-Message-State: AC+VfDx+aL7cCpkejgaty19l6xtFlhmVnL2zGREEf8FMgG7MG6a6oMgP
	Ouv7E4fTuAOCQu2hpmREV6Y=
X-Google-Smtp-Source: ACHHUZ7/anEa40S1+EyvVoXLVKMyn47JUDVS90ckUo20RZKTJfhucBW0xDyn9ZJ9G2/adwz9aU1TZA==
X-Received: by 2002:a05:6602:1684:b0:76c:55d2:a1f with SMTP id s4-20020a056602168400b0076c55d20a1fmr3635517iow.1.1683704962242;
        Wed, 10 May 2023 00:49:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1567:b0:32b:39ab:c07 with SMTP id
 k7-20020a056e02156700b0032b39ab0c07ls473638ilu.0.-pod-prod-09-us; Wed, 10 May
 2023 00:49:21 -0700 (PDT)
X-Received: by 2002:a6b:e002:0:b0:769:aa89:2403 with SMTP id z2-20020a6be002000000b00769aa892403mr11426250iog.20.1683704961767;
        Wed, 10 May 2023 00:49:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683704961; cv=none;
        d=google.com; s=arc-20160816;
        b=p5hxR5FP7Bpn0CXSlJKpAPvJ2l8djMFbbfosc4dUB0RY/6MtWaom4xm2SyMmeMoIVp
         j4LprDSKa5AghahX9YmPnA2FaIByhDfyj4BnFE4QgGgnuw03uqu04iIyKWdip2dK4Yhf
         Cts9XJr5gBRR5dc9QrGjNtT8G+/G5ZFmM95G1qMyqVoRsmPI12ID0OpQdtxZ5BA1VWLi
         9tnARWQQqnC4CkItLySTmOo+cnxkG8IUz7XW9ZdFPy2wGsQq9nODG+eqg1V6Et1Nd0DT
         v6h7FJWU5VDZ0G/Q1/oz0sbBtOuhCv4HmCxabovqmhvVcLQymL8zbC+8Ajvy6AHcKNar
         l21A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X4Vat4zi6hI7uH6FbqQgS6W+pCxYN7Uqw7fPhKVJHxA=;
        b=p8rRawEX3EhDtEP12QCRi+bpZkWybiqnqpCR9sLhcxUaEpCv6UkOQVLkodVAR5fZdS
         8GAnwQdShAUud+XV4IhBD5WtY2EYFHxOwxNco4HDlLRRuEiaSvSQ2y89HjoPl4U/37Su
         4+JnQhjmsBmTprV0kOhe4OWITvLbLCA5460klTC6MWX1jnIxz5feFWYNgUj7VuWcAg3b
         szrV91cH+ZOKzomDUV2aGUVgNrAWfDAOad5+DKUEQCLsERsZ5fXKqR/K7gJ31+7o3beX
         UIb+rIJnsfjL4w1f1V5ZeTWmIIxv5g3PizrotpI38kVlJecjADn/FeazK3SbegLj5Tc6
         fMig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=yioaVO9g;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id l12-20020a02cd8c000000b003e7efb1d848si1080609jap.3.2023.05.10.00.49.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 May 2023 00:49:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-b9daef8681fso5946810276.1
        for <kasan-dev@googlegroups.com>; Wed, 10 May 2023 00:49:21 -0700 (PDT)
X-Received: by 2002:a25:50d3:0:b0:ba6:1b1f:5d3f with SMTP id
 e202-20020a2550d3000000b00ba61b1f5d3fmr3261567ybb.51.1683704961333; Wed, 10
 May 2023 00:49:21 -0700 (PDT)
MIME-Version: 1.0
References: <20230424112313.3408363-1-glider@google.com> <6446ad55.170a0220.c82cd.cedc@mx.google.com>
 <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com>
In-Reply-To: <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 May 2023 09:48:45 +0200
Message-ID: <CAG_fn=XmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4GK+0ug@mail.gmail.com>
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, andy@kernel.org, ndesaulniers@google.com, 
	nathan@kernel.org
Content-Type: multipart/alternative; boundary="000000000000210c4b05fb521caf"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=yioaVO9g;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2c as
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

--000000000000210c4b05fb521caf
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Apr 28, 2023 at 3:48=E2=80=AFPM Alexander Potapenko <glider@google.=
com>
wrote:

> >FORTIFY_SOURCE  glidear
> > I *think* this isn't a problem for CONFIG_FORTIFY, since these will be
> > replaced and checked separately -- but it still seems strange that you
> > need to explicitly use __builtin_memcpy.
>
>
Or did you mean we'd better use __underlying_memcpy() here instead? I am a
bit puzzled.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4GK%2B0ug%40mail.gm=
ail.com.

--000000000000210c4b05fb521caf
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Apr 28, 2023 at 3:48=E2=80=AF=
PM Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com">glider@goog=
le.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"m=
argin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left=
:1ex">&gt;FORTIFY_SOURCE =C2=A0glidear <br>
&gt; I *think* this isn&#39;t a problem for CONFIG_FORTIFY, since these wil=
l be<br>
&gt; replaced and checked separately -- but it still seems strange that you=
<br>
&gt; need to explicitly use __builtin_memcpy.<br><br></blockquote><div><br>=
</div><div>Or did you mean we&#39;d better use __underlying_memcpy() here i=
nstead? I am a bit puzzled.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DXmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4GK%2B0u=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DXmSbaMQQAwCWVmZ8UYDrsmeQWiqi92Vi4CQqy4=
GK%2B0ug%40mail.gmail.com</a>.<br />

--000000000000210c4b05fb521caf--
