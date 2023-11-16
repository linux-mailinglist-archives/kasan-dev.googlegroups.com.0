Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLPA26VAMGQEQRRHJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 396C37EDE93
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 11:34:22 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-357f318d076sf367235ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 02:34:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700130861; cv=pass;
        d=google.com; s=arc-20160816;
        b=G9mXEGhSXc+mal+tyTj5gJkULHySzJtn+hUsX41FjxrJ0tGD/LbkhC/J30dTOfCidR
         a5R86z2eyJZnju7wgTCTrABmlpN1Zyrhj4IUgXz2vuzuDeiDdutJ3DuN0bcvHEnsRFSd
         bcs0CwrMMWL9JLeY5Bv97laznPyPgZQBQrMBP5jPXM2Kk7zxFXlTlUwpw4ST3bAbC9FI
         8ukfNy4vvjo28+WtO7w4xgLYIsYafpudsFFREr0LjGlWYN1u6giBosDJS7osCbdHIJwv
         S88C9smoBbDjQj3WTFalqnkAVtUd8z23KxSjQwjXlGqt3qmLKAU1YEevIu+EWYdW2AX4
         FRbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zB/6Qu3GRpr8X2gR+ubHh6cjJ7qbRsCfFrhwvKuyknw=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=g3QIHgI/RpV9WFLSnv5peqjGCoRQYZQ87R2uimQAh75q5NRRtOTLFlJ2kc4vDbQWpm
         U2RXgPy6NpCDFwNabg13BWT6jA+uoAKPWfWovvx3nfg5AcYteRqvIK/jXaEU7FnEqjGc
         /Vr24joJ5FiphUKsuqtLY+rDHhC6WD1aRtKAfAyAXA3rJzwvu/d6d1u9WsEq0R1qOM6r
         mUS2ScRVcaTgIpAQOhpnyh5bIT7TfAqLdqQGPHLKzjclpWp6y0dG3LD6SGPCENR4L6e6
         BwVLxCjFjs3ZpIr+G5Cef3a7OiR2GbQE2PRWEZ5avYnD4Vt8gfDOKZGGRI/y6wUypCCv
         pI2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M0K6ivMx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700130861; x=1700735661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zB/6Qu3GRpr8X2gR+ubHh6cjJ7qbRsCfFrhwvKuyknw=;
        b=JuLFr/3GQol5xQGps5uwF7aRCu4Kz9KWq/g/GdqfA1cuwVjYHwOZ4dnT6HeuRseKNS
         I5JEJH1PcDjJ/uhkHETjwgLwustI4sjYYjRUNLVdA6zQRICtMkHAb4/ijij2YiRL7SSs
         KuHeMoHgqH8I4Km1qMLebC/FgM0xTlquBGR9OSwUeSUtSSkFrqT9kvLAyxA4vS+VGJ5s
         z3uhQrQsIYfZg95a1JU8dHqAVVXjNPZLL4q7ahCLaM0fRT5ppQZn4+9El4Ya838zyC5S
         dRYYSJmdOr/Cu6AxWe/ZPFmfNyNLFWeI9ypTfTFWqCDd/DnDTWkn6xzPABpmImhpirau
         iQqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700130861; x=1700735661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zB/6Qu3GRpr8X2gR+ubHh6cjJ7qbRsCfFrhwvKuyknw=;
        b=ow7b7AFIB5W7PBmwQfjPS24gSFJWpR/rqBt80dTMZA7yUJEh9B8AvgrWEMh0RoueOE
         W1vW44yfHXia7O4OudcDtWFEbBnj4vrsPPXkS3SYeihga8Uto3GPzwWMBkZENe6uZLp9
         2DcaImeCnzEUmGaujlZEBTCB7qfVHdDhS33e4k1afeIWU/MB8sJNQv9Ap94tXVoWeAMZ
         qayLJPz00eqMhLH62xyV6BaLyIz6h/2NLSkrH84wFrxwW+lKZwvnEgFOlpBFA/MwMeoF
         F7oVrUGKFja8rK46I5xSgIaxkxIeRtl3Z6AHE+h0GrT1m+WZrJ0yoBvrMjU4FWirW2Q4
         nNzw==
X-Gm-Message-State: AOJu0Yyj6gp2EL9HZ0C/02h4OghF5zMXTPkvxlClKQDBl7JpWIghY9Q8
	1ImvQ2Af9sWvM/P0O83bJvA=
X-Google-Smtp-Source: AGHT+IFV1+0mrY19FHFbUn34LxFr3cPydWdILmFsZnu4OT5AeKK+1MSgUXP7FoYXA5BeTJTWsSGZeA==
X-Received: by 2002:a05:6e02:b4c:b0:35a:d1a2:123d with SMTP id f12-20020a056e020b4c00b0035ad1a2123dmr181003ilu.6.1700130861117;
        Thu, 16 Nov 2023 02:34:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3c0e:b0:1dd:651a:720f with SMTP id
 gk14-20020a0568703c0e00b001dd651a720fls505040oab.0.-pod-prod-07-us; Thu, 16
 Nov 2023 02:34:20 -0800 (PST)
X-Received: by 2002:a05:6358:590c:b0:168:e69b:538c with SMTP id g12-20020a056358590c00b00168e69b538cmr8434486rwf.3.1700130860396;
        Thu, 16 Nov 2023 02:34:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700130860; cv=none;
        d=google.com; s=arc-20160816;
        b=prFIUwI6p5lo7heRML8mRmtdYs14HbJsnk+iji/9EFh+uIsU2QmbZ7dQSmWU3CPi2q
         0ta9rtajkJr6yFmIQnbv1FTCNa8LWXzuSTtPdOURn0IQdtR42GZzK4J2wAXuadgT1kJ7
         5FhEQucusUmvxDVVZWks0p+VyIh/H4Zlzi0zq+okM1yMJbgPokS93GwEbEydOd27EsgG
         mbnZ0B14z3NWew3qJBKuUB8uWf8np27ggPEAd9UaXuWEzOYP/V1D0VbRtBbgEW3fDKXG
         RjQSOQsl71EBzflOKmRNxgsydNcVSiI/EBISV3uKUqpjKqRPRmJG1lvY9WYMtF507c2y
         Uing==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nCzmGpWmQul4wYiJvXX4QGBTD7ZNE9De5NBHM0dQ8JI=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=o3EIKMfvl737lnd73JwcYjzYTpUey0ph1B7g/c2SNJYA3eyA+1fTowAXgIrNvFxQ4a
         8fNdpBwigwNLTSVykJ/hfn0pDwg/k1oPPdEfTfZ3u6AUUp8H9HJFBIo6EKO3JUuYm+3q
         krtecgo09B+yjBKef6zhLWAGQ2Iu7agFc5RH8YXIL5TndExmf0jb4Xm+7BZ6O8WLYTe7
         HyKN/Nleb2TDw+3ikwu/c7GYBywbcdjpOPEb9BZqhyT3Vk/9NR7eb8/9KGC9C41IiJR1
         WiwvLoRHj0/vINgcf0fqf0Xo+FVhIHNorawbkj3bMfKmeCagFGsLrQAhUfg6sDNCSg6Q
         8LGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M0K6ivMx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id cb20-20020a05622a1f9400b0041812c64692si1670574qtb.3.2023.11.16.02.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 02:34:20 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id 6a1803df08f44-677a12f1362so3280486d6.1
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 02:34:20 -0800 (PST)
X-Received: by 2002:a05:6214:12d3:b0:66d:1d3f:17d7 with SMTP id
 s19-20020a05621412d300b0066d1d3f17d7mr7472430qvv.8.1700130859918; Thu, 16 Nov
 2023 02:34:19 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-20-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-20-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 11:33:43 +0100
Message-ID: <CAG_fn=VMKwcsBL4KuRYG-dojpZg0WFqJgZc67ks5Rg-HEnd2bQ@mail.gmail.com>
Subject: Re: [PATCH 19/32] kmsan: Accept ranges starting with 0 on s390
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=M0K6ivMx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f35 as
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
> there), therefore KMSAN should not complain about it.
>
> Disable the respective check on s390. There doesn't seem to be a
> Kconfig option to describe this situation, so explicitly check for
> s390.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
(see the nit below)

> ---
>  mm/kmsan/init.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
> index ffedf4dbc49d..14f4a432fddd 100644
> --- a/mm/kmsan/init.c
> +++ b/mm/kmsan/init.c
> @@ -33,7 +33,9 @@ static void __init kmsan_record_future_shadow_range(voi=
d *start, void *end)
>         bool merged =3D false;
>
>         KMSAN_WARN_ON(future_index =3D=3D NUM_FUTURE_RANGES);
> -       KMSAN_WARN_ON((nstart >=3D nend) || !nstart || !nend);
> +       KMSAN_WARN_ON((nstart >=3D nend) ||
> +                     (!IS_ENABLED(CONFIG_S390) && !nstart) ||
Please add a comment explaining this bit.

> +                     !nend);
>         nstart =3D ALIGN_DOWN(nstart, PAGE_SIZE);
>         nend =3D ALIGN(nend, PAGE_SIZE);
>
> --
> 2.41.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVMKwcsBL4KuRYG-dojpZg0WFqJgZc67ks5Rg-HEnd2bQ%40mail.gmai=
l.com.
