Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5USSWIQMGQEKWORW2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D954CEED0
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 00:53:27 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id e27-20020a056602045b00b00645bd576184sf1706953iov.3
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 15:53:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646610806; cv=pass;
        d=google.com; s=arc-20160816;
        b=BneYLys6nXhQ6fS7ee7+ZQ4nHfVwsOJHvvA4IiONUbQmXWfsQoj7MMb09pp0unBfD7
         CmHuDXVAMxSH8zLlG0rejBq1jGm2wGq0UqtYCn51ozPYd6PqP2OB3LK707Ym+x0d0szq
         bY74KZuGXKJiPtTjf+pXxtQ6D3WriDbmJNlgIbCUElVeaeS6SJsKsZeN28w6KfTBCNjT
         HXNn87dTDuWfO78gHSZgP7BfjJvQmQ3w0+33VTghLOZQTgqEJOv16ReZo8ktJ5V+wJeJ
         DYjoEU3hkocxeMdkVcLOcIVai3E2M0pP0yZLzyXX1AqqYiOolh66jc5j1chT4Fm2cAhW
         ZDQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yDxjNiorCRtQ2Ld65qv1yEGB4pDusJvEu5G8k3tLQJ8=;
        b=vgTS6TXbVKCFmQCFX9Butza/aLYCKE39OYOCyQ6k6eFL/TotXpdiq7nMP6ONJIB5AW
         aZqsT5PXxjxDLvRCvZt5h6j3zSITYCW5ncZArY+yEn5+khW6rLc0KpBYMMktV+7CLPXF
         NBf0TzaS/NV2wkbIyagxZFarNSHnPx0IiG6x3rUNfUCLwR9jW2AYDtmSl/AZfo78VWpq
         fSqA4pT8Yp+65Ruq4svX1Bx43oEQ2ddPVPR4RYkz63GFO+1qnK3z+vos3BCIJmuoyXhp
         aCpj2gqvRDpGPn4TkF4hSmgxTM18h0wv9b/213PMRMUKDgvbC6IFhI/Zoi5ZzZS75Rf3
         1L8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IHktzUDV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yDxjNiorCRtQ2Ld65qv1yEGB4pDusJvEu5G8k3tLQJ8=;
        b=OaX9rtQqc9/bL/0of+5AniCGli1ih0RoHjOEX+rF2JrTf1kw7+DLedVcxVHP5DefS2
         iayjILDOJEy7a+pMd3Fv1RyQei3ruUdiFcphI8IAN94YnlX4LGjzncjhTN+1lsYmj5/P
         mI9zPoXPCVgYrmXx1pVPrIEy9m7F/qDDFQRWUIkofQdQrGivCNDvkd0OcliSlTCi/u3b
         O29jmUSS6T8OtZKfE9JgfeukQFziEH7B4zD4jHncOgkRbQOKLf4Ck2aljU4fUsHWpKO+
         ujt84RaWSXjjP8Vp3XSA56HQX3JYtcKUornkFviMj1ByBmwE76u6Q2KV49I61DWht4lz
         TW4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yDxjNiorCRtQ2Ld65qv1yEGB4pDusJvEu5G8k3tLQJ8=;
        b=ARPyNq88YwauWAiz3SoAqXnt/ysnMoqoBpLdkpR9RxElxMj9TW18XyrNM31Ncuc4Go
         XBsSNJmdojKYRSpX2BoCgK6bNZKxLxOI3kmL2J7ftG2l49/98KpFeuitXgJUykQuoGCo
         G3IYqPTFAWcBFf/GbaHrjr2jvt4xl3GcpwpsTTLn/8ah5r4UEorHRubGixvGt+r8zF0x
         VN/RTdP63o3l3P3s40+ssS22/Pp0yQ4LVUTZR64eGNNAWarEagJEY/eodAtDGRFK54ZU
         exx7n3ZOlPBOqb7PkTgS9tCQtVmTp1RGA1524RBrjO90FlTT3nIq4q93AYfKIpWiiKl/
         Rl/g==
X-Gm-Message-State: AOAM533dkWjKs2Wqqihk/1K7EWdfRqA6jL0zc8zykemcCy4i+U+hsYOG
	T62ly7OvWnRFo71wXQg+CXk=
X-Google-Smtp-Source: ABdhPJygesx2D+IyKst5wGjtnYcnC0wMyp7x49RSvqqEDqz8LgGrT5Aj77X5qOz4Ooqma5WBI1lpyA==
X-Received: by 2002:a5e:a70c:0:b0:640:dd42:8e95 with SMTP id b12-20020a5ea70c000000b00640dd428e95mr8208231iod.140.1646610806092;
        Sun, 06 Mar 2022 15:53:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:35a8:b0:311:86a9:1cf8 with SMTP id
 v40-20020a05663835a800b0031186a91cf8ls1818791jal.11.gmail; Sun, 06 Mar 2022
 15:53:25 -0800 (PST)
X-Received: by 2002:a02:c6c9:0:b0:308:3586:f407 with SMTP id r9-20020a02c6c9000000b003083586f407mr8782051jan.173.1646610805681;
        Sun, 06 Mar 2022 15:53:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646610805; cv=none;
        d=google.com; s=arc-20160816;
        b=UILhfERK52tMGZ3STWczOLxLicu2m38XK6XU7CPhwm8QUJaOV3wghVD1kWZ+1yfH6u
         YifplNAAFaBpkX8/OFBP5Pj6WaiDSMLBpFxXbKjHyBW9UAAaQHndO/WVXxphDAUoyRCK
         DzmRFX/qPvkKdZs1g9cdd7WOzqpNhY8nlof0HhnKjIcNusdxJhh3QbIN6fAtUEq/tV8p
         JrYh5ROOrf9pn17MIpfY7yQ76oZ8OMuAsbw8uRbYLzuLeaMgDZ6gSN3TXnxIR0+ftLVy
         BSUD47ojC1ECU8pw/z2XYxuv3mjP5K9RyRkra69GZhTScpvw6sOxal90KZ29qEgn/c/A
         nCKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MABB9jbYy82t2uep+ZIaOcEDc6tX3sRenZED6Ge1JDM=;
        b=oBJGS0jgLh6cjM+O/o20MkTd2HrkrEFL1hEyA1grpT1T1Q3/32njzq6KkVL9kYmnIq
         BjW3tV4L7Awec6Xk4pcsGnaKZ7JMRwWPh5OqhUdIyEAL+7foQIAyxE29IRDs+eoh4k5q
         5f4ibSWfkiyhzgVFR/8gLuFi3C7oXGlnFJlYK2CaYqUKqnp2SgZUZfmxJarKFB0CjMGo
         rhjXRxDs+0phWnCeaT9Nf2JR+hJaqlAKyq7Lkh17Ot8paMP+m6s7lU4/aKO6MsNqIVUR
         ZL+AFLR7YVYNw+YhwOgAwMVuCzIvq7KKeB0CHlPzCxsT5KNVD4YVxnZjdjzVrpYaMgUq
         YxUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IHktzUDV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id s12-20020a056e0218cc00b002c1a7c1011fsi537086ilu.2.2022.03.06.15.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 06 Mar 2022 15:53:25 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id x200so27740531ybe.6
        for <kasan-dev@googlegroups.com>; Sun, 06 Mar 2022 15:53:25 -0800 (PST)
X-Received: by 2002:a25:6994:0:b0:629:1e05:b110 with SMTP id
 e142-20020a256994000000b006291e05b110mr4736034ybc.425.1646610804997; Sun, 06
 Mar 2022 15:53:24 -0800 (PST)
MIME-Version: 1.0
References: <20220305144858.17040-1-dtcccc@linux.alibaba.com> <20220305144858.17040-3-dtcccc@linux.alibaba.com>
In-Reply-To: <20220305144858.17040-3-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Mar 2022 00:52:48 +0100
Message-ID: <CANpmjNM+47dfjLyyuQwUWZyJgsr1Uxd72VPe9Vva3Qr2oiXRHA@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kfence: Alloc kfence_pool after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IHktzUDV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b29 as
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

On Sat, 5 Mar 2022 at 15:49, Tianchen Ding <dtcccc@linux.alibaba.com> wrote=
:
[...]
> +static int kfence_init_late(void)
> +{
> +       const unsigned long nr_pages =3D KFENCE_POOL_SIZE / PAGE_SIZE;
> +       struct page *pages;
> +
> +       pages =3D alloc_contig_pages(nr_pages, GFP_KERNEL, first_online_n=
ode, NULL);

> mm/kfence/core.c:836:17: error: implicit declaration of function =E2=80=
=98alloc_contig_pages=E2=80=99 [-Werror=3Dimplicit-function-declaration]

This doesn't build without CMA. See ifdef CONFIG_CONTIG_ALLOC in
gfp.h, which declares alloc_contig_pages.

Will alloc_pages() work as you expect? If so, perhaps only use
alloc_contig_pages() #ifdef CONFIG_CONTIG_ALLOC.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM%2B47dfjLyyuQwUWZyJgsr1Uxd72VPe9Vva3Qr2oiXRHA%40mail.gmai=
l.com.
