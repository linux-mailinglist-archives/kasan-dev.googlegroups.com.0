Return-Path: <kasan-dev+bncBDW2JDUY5AORBYNVX2GQMGQEQ7GQY5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AACCF46C1DD
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Dec 2021 18:33:22 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id v13-20020a056830140d00b0055c8421bd62sf5957351otp.15
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Dec 2021 09:33:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638898401; cv=pass;
        d=google.com; s=arc-20160816;
        b=NBZHXc+Gt9cbLM/O7deLsxOUjdJFcjTwU4Aegkn69rEv1cISuJA301WUs2zhkpSmoz
         uqFNtzNtD0RvNh19HsZN0/fgbbWxOhjD+7EtRLtfpqFZyeaeVglKgTdakfJ5wHCTzexx
         DodsljgTqZZ7Oc3iP+Vkj4X+mKJ4C9VC4H5nKpBZrwslSOvFD30yU/KuqvEDK6EHqhnS
         tdlHwb8St+4T6XwZHNN6Cz6xmiQF9gLWlW3xw9g3SMjQ3Q1Lz2mCgiQluSNe4nsi1312
         4w+8C0p5RnfYOlCKRv8D8imfuLBpFNe6F4B9IZ01NlGmJ+8f0hb9WmWSteCvt+5nR9Uy
         eEvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lLIAfJCpvQdf/0J34GtzAYvxszfCLKdw/3coISrqjQ8=;
        b=fyFLY2Ry58v39GtFuA9/ZTVYJnezmncNf2yiDIT0n1DbA8Xe+fuNiq70Orc6kxR5Xo
         S5sMk6EaiUI2EqNzsna+06gT1VaGD/7TJc1YKKMqXgc0DQ4DerYH/F3SnufXTKmBDebT
         UCw5iSlSeX6vG6n+3dvzPxPYW6rsYhtaPlsEi/GfL0izeDRaWSogdJ+MTXixN/I/oIv1
         egFtJ8VZykB811wpxqB/UWX7z1r3pyHKODBKVroGYrbojkfvqa4Afr8XlOwnL0y7j6V8
         /71KdxPfbWvNHl2QvWnkGgxlVKXsnWx+v/p5HWyytrrAEV3AKFKllFfVC3QXS/zUNVuW
         HjMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="M+Y/YJt0";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lLIAfJCpvQdf/0J34GtzAYvxszfCLKdw/3coISrqjQ8=;
        b=L7Gb7uM4IiIo+PVaCK8O7XywCvoGLK+4mBSUG+Y6ZRIaZdtZGSkcYpsjnaYhnSXbCr
         w+QWEiWQpaxhds7IqHawnPf23/75Tqtvk4FBUrPC/WCtHatQ5ztROOMdtVrBqO1Ke1Ml
         boZvh0rXuvOy8ntaARuOU5TM52sZSLk4Zn/WI+A387/j46WYAxhslJsUtGR4ysjQyVrM
         eki8QidYw2tiFijEbWzQ3xiY+9WLvK/xkOeYmgpBRoWMUFud6CfObacVXbydSiGbmXb+
         M9t/lt5ig+YJ2f81mUPMZAkkmKNM1KXhGxgHo+Xi6FmatMP6+A49ufR/EngJ8l922hbq
         6CKQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lLIAfJCpvQdf/0J34GtzAYvxszfCLKdw/3coISrqjQ8=;
        b=dywnDAif/7j6wj4iIMy3oaezlbOFngunTBxRsv7+ggpDLTyoVZIrsz8txBY2C7B0b4
         BA2JNcCG0opmszbpqeN4Vi1nrYM69FtsMuE4J25IGMmahFv64SW8qU3kQ/P6x6frybL4
         aA/d2Kiusw6Yyq+bMRK1dQJI7onvwLLxvc8KjykXxtS2BqG1dqwdQVo2AesG3DvsP/wJ
         mzBVfpVpC1I0awAW2vH/vS3Efk/GZBBsFI/pUvhSMUL0ZoJgakLlmmsiqaVuhGRLxDZS
         cFq2MWaF9u6Ds+m3Ymds+12hAyJyQtTy8dyEXuROYJ62PTZT4htgbOGZ6WShBU2gZJzo
         JveQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lLIAfJCpvQdf/0J34GtzAYvxszfCLKdw/3coISrqjQ8=;
        b=1MJpWTwy20668k8F68lFqBFc49LcIMu1nJRNlZ4ws8A89dHmmdmZnCrsSneOU0uEsk
         vCM5VZpnio5wSIGvKOACotnE50AYapA+1udt8VWVv9cSGRYXlLLH3oGhPsBI13sAQmnf
         lY0YT6if59PL97iC7PTQ9waQ9u5nZyl9Z671+A1Pswt2B0YbZoGz04dwKg2LlTTYTY1U
         DE/ATREwhKElGZVYqiw4r4gpLXZ0383Vonav/jR/+X4GVhNYuCxfNT+H0eN6cwJ8fFM7
         E0THJlSj++dfPEWXhl4e34O4ZCivBW221y9vDWcGlkWvwEgHx6oKCI3RpM6uAIO6Zimw
         dPLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532m3VuTegTYr1M2jRjJUV6EtTOvVzaAXSP/1j+wXrncGL2QvtAn
	P6aWpNoazN0sogW9K6WS4N4=
X-Google-Smtp-Source: ABdhPJyZ/KFGcyMF0vO0PCHU/GlsDO3xyuOwIW3bc0e/yK4S8sI+JiiQiJcdRfpf/PIfLf1sQtix5g==
X-Received: by 2002:a9d:7f91:: with SMTP id t17mr36025707otp.197.1638898401412;
        Tue, 07 Dec 2021 09:33:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:219c:: with SMTP id be28ls7869314oib.1.gmail; Tue,
 07 Dec 2021 09:33:20 -0800 (PST)
X-Received: by 2002:a05:6808:1210:: with SMTP id a16mr6322069oil.161.1638898400820;
        Tue, 07 Dec 2021 09:33:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638898400; cv=none;
        d=google.com; s=arc-20160816;
        b=R7PfG+bbCarlThUhR8PGeBgxMHow9lm+b72R0WEtdWy6SXTupp7WOiEhHnH8R5+UKi
         eqtgIXuFBd4gubFnkU+EdnX919hoB4l5Az/cZw/MhMi7qro7nJsesbdiwnshEuvtbfTx
         llbS8YyylJ43Qt0dwdbbTP4gvsSSwJsiH9Jf2jQfWR63O5HYzQFcaX7a9b/xuK7fAYiB
         ZoVxdn8ETUtINpV8lvH8aECKgeEPygyKTGOxRKDv2TfIILYpwtYwDBoIl5Zv5ZCJfSR+
         1Vcls/vEywCNsC+lUZb2DXfCdfkXjeiQCxp+KSRtHTHBObvvICWfylnPNx8TdhHKcqdg
         jgEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ItbOlealijmUoY42Kqnrg2wEzqeEb/n2rzZw9C9eu6A=;
        b=Bju2tTn/RMCed41ZpGyV5tAhC80lR9ANzR4hzfh2TsHiXM1fTQ8lF2JERKYXYzTY4U
         +7r7Am2O+5/3c8cDohEeV8v3VsH0p9UUGYgZzg2lwmEXTkqf3YixK+fox/TGj6Teg8QE
         0QE37qaYOdhnvJsQTWKUUyFQ1TZBj7CrM+jUcSZn8wJ+t7EjCYFZu75DQ+8rT6tX05Vx
         dvgqldbonIKzJ0ZGmMe3iPZw2HJQ61vTwqWa6hcr8dSb/7bsYXmkpgrMr9L4wZvgUt8V
         lGzzy1LeF/0FUx442PDoJ2U6Dfn5dT+zDgJ0ryftsOsqPck7r0TCOh5YP5IuzBSREXTy
         IIDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="M+Y/YJt0";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-a896ac0ff2si580fac.0.2021.12.07.09.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Dec 2021 09:33:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id j21so14630276ila.5
        for <kasan-dev@googlegroups.com>; Tue, 07 Dec 2021 09:33:20 -0800 (PST)
X-Received: by 2002:a05:6e02:1a69:: with SMTP id w9mr726522ilv.81.1638898400487;
 Tue, 07 Dec 2021 09:33:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <a2b2528f6d96fbc6a0c68f16e7212f80f3ef1505.1638825394.git.andreyknvl@google.com>
In-Reply-To: <a2b2528f6d96fbc6a0c68f16e7212f80f3ef1505.1638825394.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 7 Dec 2021 18:33:09 +0100
Message-ID: <CA+fCnZfQr191GvWf+T2=HB3bLK2-sE4DgHSJcXsahM5BN_nPPg@mail.gmail.com>
Subject: Re: [PATCH v2 07/34] mm: clarify __GFP_ZEROTAGS comment
To: Peter Collingbourne <pcc@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="M+Y/YJt0";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 6, 2021 at 10:44 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> __GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
> allocation, it's possible to set memory tags at the same time with little
> performance impact.
>
> Clarify this intention of __GFP_ZEROTAGS in the comment.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  include/linux/gfp.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index b976c4177299..dddd7597689f 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -232,8 +232,8 @@ struct vm_area_struct;
>   *
>   * %__GFP_ZERO returns a zeroed page on success.
>   *
> - * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
> - * __GFP_ZERO is set.
> + * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
> + * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
>   *
>   * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
>   * on deallocation. Typically used for userspace pages. Currently only has an
> --
> 2.25.1
>

Hi Peter,

Could you check whether I correctly understood the intention of
__GFP_ZEROTAGS and give your ack on this patch and the next one?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfQr191GvWf%2BT2%3DHB3bLK2-sE4DgHSJcXsahM5BN_nPPg%40mail.gmail.com.
