Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL6OSX3AKGQE67B6WGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF93A1DBB1E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 19:21:52 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id e44sf4534818qta.9
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 10:21:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589995311; cv=pass;
        d=google.com; s=arc-20160816;
        b=D2wvI5DvSqkXsc/YrNZ2g2z96HcidUxmcY6eyA/ueWzDCBTgdVRVhRTSIU95US+b6R
         KwCcYjU7pu4rrvMlPXKxM9wJ/qsrtWuKhGP76/GKYZkFBe2tEDTUkOnFTEChrXIZVHJG
         lG7NXNIdtpx3tJXh5GRrnk5TWxxNSDCvw346MtRicQeggYfEaZhJ+xRsKnVUT1HXUKau
         Oghc2pGtmhy8VNUtUfFfphOR+J9vulKXXEMUaMrwxH334DAIhqwhDdXmULnxjq9XnD7/
         RxW7KgFPt07Hdv7CQSyD6FIQftKW9krrEXm9HNvzzF28Inszs1sWZpvAsIh/Z3I6qxKd
         US9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BHQejhH0FzNMCr21CqKBLVIzpF9zB0wv3zaikK5vork=;
        b=sntoUjWib4VLif5IHqn2BHNeuCz9eDqo2K6Weot+LPcI6Ne7V/ZKe9emWAuTiXbEBe
         MEV87MQwpjHwrIZMjtWmLNZ7SOH6khJg2JRD4PcUAI5fFRjt2fZNKJZx/N0rlDkL9IIv
         z4ZnMj6aolDu/6JOYlyhQ36C0gjXHvXYtOLwo2jheb4TQoMlK4F/CDBCxaqAF8K1lb1d
         oQRTAfOwBgejbhaP5HhmNhSyAjD2aM+ES97mLJhZyA2OCjO11CvRQw7Pcza+FfvqAavJ
         eiGzoTsvo4I+5JfWppmYGYk8Bp5Pr++JWs/4xAM+O9BECbxuEplM62TQ6zRmqHMUzOEs
         4iLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CZl6CsFW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BHQejhH0FzNMCr21CqKBLVIzpF9zB0wv3zaikK5vork=;
        b=fC2Wn3FkqWM8sN4Yx1h0hjRTj3h4Ef7KcVJCru3XffDwbJVckXt3RvS0SiEAqkyWlO
         drohPNl6ohXwzP/2P6O1xQVwi8ZCM1ZTdodTvZsDn5bt7GECSRGW1rBwKLbFdKw3235O
         oyu91OxWPmYHeLOK2UTt3+6oScjG24s4SCj7asWbKG8Nx3+kEU9HpRU7F3BreGdpRnwZ
         2zhcnkR9Iu84E4+0P2DJUTLVRuyeytzaAiyX2C9ndXE8q3uUQQWFOCwlqIbyh6sYNCo/
         auGZZSZkCLmP0hU4ZTI2L33gdi0FxKwBcv7zwd7T2XfHaqeFrzm6gM9Eu71UM9tJ8KAv
         7vSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BHQejhH0FzNMCr21CqKBLVIzpF9zB0wv3zaikK5vork=;
        b=X4eTL9N1GqySjVePpr2+GwaSZqnowlTtktHc3FoXTlS0d1/PT620XsR9A/Lm1JKNco
         edNBUSZbkI0d3bUWbugOeB+btKt3zAHIkxryd8RLSn0+0sJi4qKP4L2Ug04e7d4YFD1I
         OYEUzWMPV6ydIRTBesh0EMA2k15Igna6fk67P3r0a90f84D8NNsNuVLH7lCwa88HHPmJ
         PL3OKDNB+JFrGQ9P+w7qXNjqGZhJZpFhRKWwt2Zy1oCZzdXTy1+q1zJ+Q2NYVUYkpoMf
         10fYBGy1kLka4OGtkzDd2AAldZ91hmg3yDQc8LN0Bb9Pbso4Q0Goy8VAaTvzE2dmCfeR
         Vgbw==
X-Gm-Message-State: AOAM532WZYzBruoQ7UyVN1IUbTh7pW3mfi+vYaVkbhMfxtKqH+kVugHe
	QKkNkV+CJs8ZyPQmoYw/uyk=
X-Google-Smtp-Source: ABdhPJzQV71igXImNXj4Otaclr8da4hSKa8BNs+lhck328Bxt+Qrhl43PabgCa2LGIeSGTvO3m9E4Q==
X-Received: by 2002:a05:6214:15ce:: with SMTP id p14mr2648758qvz.159.1589995311285;
        Wed, 20 May 2020 10:21:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:655:: with SMTP id 82ls1989033qkg.2.gmail; Wed, 20 May
 2020 10:21:51 -0700 (PDT)
X-Received: by 2002:ae9:f445:: with SMTP id z5mr5995163qkl.169.1589995310448;
        Wed, 20 May 2020 10:21:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589995310; cv=none;
        d=google.com; s=arc-20160816;
        b=qooFwJ3ahhDYEoDIF9MHxCgH5Fg4VYn5ggaOQzEMQAaBKHdrSZtzpWWrinuhTjSxHG
         Ls4HHZIdrjS/fgP/Ei8qADa9SfsYtgs57l381AMGB6/MlKGkeiD/i8VDoZ/9fCtap1vx
         zDdaOMmjaN424+hq/xPoKBAHc+8IymB6x2Muv1FdUlp1x/4n7aTph7Fe370JDkNytgkL
         xVcws8DmPFS7lKG2cn74voXosWpihs8M2Nw/8SfOMoOkTofNsaUVidUenCBmcweq39N4
         9/6p3wFL7Q5YvCQ+TADO6f3SNzB3CMoRM7ZWA+aQe9PLPqyfHDZL/0QMAC3gWDEYmUE9
         tcWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=95NoVwJoVbRHYEt2LwkzPQkmEJEgGiZNXsMW4rcmrmw=;
        b=ciW8IUe2xdDGUMeXYlmpUmKOQ/v/yP1uurdfBF1AF1WYkC7+A1U7vEkZE+x7cl8UXy
         bg8f8+mZUOlSxQk7Rq6aJlhx/+rC4VNXW8gRgo1iWZ7iwn4Qm2psh5yJwJ4jjhhOjJIT
         t/MiKqFeIYLw7gbijeDH5hndidYpDOCf+PjuwQeMDUXBjHEkagaTToEjaRalyx599c15
         nDMD+8oxv9XwvwaAGqIMU4a1bK336Ut2P5rH/bS8v6Pa0OIrXhgy5REjBh1P9udD7Nyd
         P8PuArL3GuOp9nZQVTP3V/3+5rQl1hW5OCS3s9ZuUFrZvH6pzV9KS38MlOYNSLomYvPg
         GC1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CZl6CsFW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id e17si89174qtw.5.2020.05.20.10.21.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 May 2020 10:21:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id n11so1732288pgl.9
        for <kasan-dev@googlegroups.com>; Wed, 20 May 2020 10:21:50 -0700 (PDT)
X-Received: by 2002:aa7:80c8:: with SMTP id a8mr1186016pfn.318.1589995309357;
 Wed, 20 May 2020 10:21:49 -0700 (PDT)
MIME-Version: 1.0
References: <c9ef35d4-5365-4e37-9e7e-68bad7355c21@googlegroups.com> <CAAeHK+yOPwwoq-1X+4D_CVKB9n-6A4ZP6tYLT1mpJ3O3C2b3+A@mail.gmail.com>
In-Reply-To: <CAAeHK+yOPwwoq-1X+4D_CVKB9n-6A4ZP6tYLT1mpJ3O3C2b3+A@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 May 2020 19:21:38 +0200
Message-ID: <CAAeHK+w4KymXpgEtp2n-7TCwkiVaBMZ+ztfmkYokg2f6hG62Hg@mail.gmail.com>
Subject: Re: Doubts about bug types reported by KASAN
To: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CZl6CsFW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, May 20, 2020 at 7:21 PM Andrey Konovalov <andreyknvl@google.com> wr=
ote:
>
> On Wed, May 20, 2020 at 12:01 AM =E6=85=95=E5=86=AC=E4=BA=AE <mudongliang=
abcd@gmail.com> wrote:
> >
> > Hi all,
> >
> > I have some doubts about the bug types reported by KASAN.
> > 1. In Line 126 of "get_bug_type", it verifies if the address has the co=
rresponding shadow memory. However, from the description of KASAN(https://w=
ww.kernel.org/doc/html/latest/dev-tools/kasan.html), all the kernel space s=
hould be mapped into the shadow memory region. Why there are some accesses =
that not mapped into the shadow region? And in the code of "get_wild_bug_ty=
pe", what's the logic to distinguish each type?
>
> AFAIR user space memory region has no shadow. And if the kernel
> directly accesses the user space, KASAN calls this
> "wild-memory-access".
>
> >
> > 2. How does KASAN add redzone(e.g., KASAN_PAGE_REDZONE) for Page-level =
allocator?
>
> I don't think there are redzones for pagealloc, AFAICS
> KASAN_PAGE_REDZONE is used for redzone for large kmalloc().
>
> There's a bug entry related to this:
> https://bugzilla.kernel.org/show_bug.cgi?id=3D203967

+kasan-dev

>
> >
> >  60 static const char *get_shadow_bug_type(struct kasan_access_info *in=
fo)
> >  ......
> >  76
> >  77   switch (*shadow_addr) {
> >  78   case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
> >  79     /*
> >  80      * In theory it's still possible to see these shadow values
> >  81      * due to a data race in the kernel code.
> >  82      */
> >  83     bug_type =3D "out-of-bounds";
> >  84     break;
> >  85   case KASAN_PAGE_REDZONE:
> >  86   case KASAN_KMALLOC_REDZONE:
> >  87     bug_type =3D "slab-out-of-bounds";
> >  88     break;
> >  89   case KASAN_GLOBAL_REDZONE:
> >  90     bug_type =3D "global-out-of-bounds";
> >  91     break;
> >  92   case KASAN_STACK_LEFT:
> >  93   case KASAN_STACK_MID:
> >  94   case KASAN_STACK_RIGHT:
> >  95   case KASAN_STACK_PARTIAL:
> >  96     bug_type =3D "stack-out-of-bounds";
> >  97     break;
> >  98   case KASAN_FREE_PAGE:
> >  99   case KASAN_KMALLOC_FREE:
> > 100     bug_type =3D "use-after-free";
> > 101     break;
> > 102   case KASAN_USE_AFTER_SCOPE:
> > 103     bug_type =3D "use-after-scope";
> > 104     break;
> > 105   }
> > 106
> > 107   return bug_type;
> > 108 }
> > 109
> > 110 static const char *get_wild_bug_type(struct kasan_access_info *info=
)
> > 111 {
> > 112   const char *bug_type =3D "unknown-crash";
> > 113
> > 114   if ((unsigned long)info->access_addr < PAGE_SIZE)
> > 115     bug_type =3D "null-ptr-deref";
> > 116   else if ((unsigned long)info->access_addr < TASK_SIZE)
> > 117     bug_type =3D "user-memory-access";
> > 118   else
> > 119     bug_type =3D "wild-memory-access";
> > 120
> > 121   return bug_type;
> > 122 }
> > 123
> > 124 static const char *get_bug_type(struct kasan_access_info *info)
> > 125 {
> > 126   if (addr_has_shadow(info))
> > 127     return get_shadow_bug_type(info);
> > 128   return get_wild_bug_type(info);
> > 129 }
> >
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "syzkaller" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to syzkaller+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/syzkaller/c9ef35d4-5365-4e37-9e7e-68bad7355c21%40googlegroups.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAeHK%2Bw4KymXpgEtp2n-7TCwkiVaBMZ%2BztfmkYokg2f6hG62Hg%40mail.gm=
ail.com.
