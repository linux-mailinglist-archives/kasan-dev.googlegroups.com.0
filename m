Return-Path: <kasan-dev+bncBDW2JDUY5AORBPFZ3KUQMGQEIBJTYDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 99C2D7D3C20
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:18:05 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-1e96efd9ae0sf5484964fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:18:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698077884; cv=pass;
        d=google.com; s=arc-20160816;
        b=fl7kTq6KEnF/bxE32vUcVITNRxNVUKyHzbb5h7oY+ulPNJMjpTQsRzx9xAP69KAPqw
         UE/tVYx8fZP+EmiOeLgVWGExVeWfGcygE5Ed64QeILohRa5luSPsFXyRr8pDYJylN+OJ
         zd28jTQEQoEfVcsZzsfAf0/oCo5x6fRKtZZUDoykRv0lhmT5Iqw7IeBXT7KVk+kn/cje
         GG2RELqgeat9vGSmFMCN7df5Yi1LfAgn9dS9tMHEilwSttiC1khjZWIxJHaK6UFW0oZ6
         oKpIoIDlaoLz9FvBVdvbCSNuZFLc4NqvOu0SWFkFtToz+jBBgNZ/BEhUii5ruo8Nkh34
         YWyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DYXp4/dRFL00hhGH4hPNuiqGVhDhIS61BPqa5Q8ln7E=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=YdGUk/bD6NSkPtbZxdjgvsS1/UFo6ZktAIt2iN8R5jqHYWzn2oSTvjao3JQcdqj7LJ
         LaEWpm+V+2Ia3YM53cx/YebwZgllBTdLrvGaI6DOHPEEAQfxa5rOThZPQGjNnU0uVpsw
         k8ku95/mssua0UAtOFaPDFgt+RenJuElljuNYG3p2mo+/Me7Sjd60ZMv/bUXG0t4m7o0
         6TOQM/c2okFia6zzUwsGRoCVoB/RMAGUQXpHfitgcSkMHX3S2dRpvV7SHUR3Tv16BG9c
         6kLE4BoK/vNHRG561e5Yo1WxRcHng3jbAn//QekamtmEEiYOfaJDdKrJBOzovUidVW7x
         BmTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Hibmiimk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698077884; x=1698682684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DYXp4/dRFL00hhGH4hPNuiqGVhDhIS61BPqa5Q8ln7E=;
        b=KnwEwCl2IyU2QIdDUsucMZqABQaiqhY+3rM2lRqyFhNABXabS07qSNaet9sIuD7CWT
         uYBmum3dD2p47/nusMepOmzegHFzx9RzSsy9sgrjew5ScGWrSp8/mtK4qUitJh3BiTX8
         uFmyy7ArpNu2A/uRm5etAg51FkAKw4rY4y+ETxWYMQnbclqH01jjaImy9ltYcvLrdscS
         BlHJa/IWdl6tr+kK2tX3iKmdxdQHd8cTLXG6So2hJ2sF7scP7YILBcPf8ZXYaAo2+E0o
         WIVomvaYNTMQrxD7cC7uOFltr0XOR3n2/iSxzOvnfn3ODcP9EKJaUep3URQaMRBeJzvk
         gugQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1698077884; x=1698682684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DYXp4/dRFL00hhGH4hPNuiqGVhDhIS61BPqa5Q8ln7E=;
        b=nks6HPBAz1DV8nFZFK+aant9VWsAZs9o6DssYHxPaiYRlED0jg0+F1spc8DfB7WywM
         ud2jO4XC8uTMNP6Q5lM8Ia0gck9TD3n2kO2BJdpFUMrlIQbULT8qfF0F2dymc1LsvPb4
         eyoJRkxfw19aAcV4poYvSIGseth4YLYgO/GDT9c/8K8fxnxyteF0HCmt0pEOAvdTUDEQ
         kZM7l1WGQin/2FlLjsfvtK0S0Il1Dex5AV1kzs4hNE8z6fCIrpIy4s9u7EDyVDaI8rVv
         UJveWS2XEEAl5rfJn3zh2/sQqJvVQK7J295jBvRdESDxPvAcNnnDVgIgO2xRKmgVVghq
         k/gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698077884; x=1698682684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DYXp4/dRFL00hhGH4hPNuiqGVhDhIS61BPqa5Q8ln7E=;
        b=wVmdsBa/b+UzqwI4axQyNNafqhSePP9Oa8VTo64Z9fBnwALokzVPJZfIhkA170zj07
         284v0DxwQHB6vZ/hz7cX5Y9YW9PQLhS/EAgmoGyAEMuRHzYCM/kiVg5vNaPAqlO06g0L
         uXYA8lqn32Jd0AJ4G9Yxo/ocLUXBWzYdGpf7UG4sxFsOr2O+xBg2DL07usFU9+8xnR35
         y21yd0VWPWikw5No5/cFDRQ8co6t3ABtrngSsYLtGzEOjZ8H8TTsHlxVYR9RD8R2xue6
         eFC8Lct7JTOaVMJnmfmbCKTPS5NurDnVhwyimM16z4YLlMkXAOHICUOLYxfmljpU2XWB
         mCKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzdhWd/VfX5VvpgJpL+d3/GBY3u4vd3H28DTRTcl2Lup3Mu/2Tq
	5l/Nf3mgmhoSCpArZp6A7L4=
X-Google-Smtp-Source: AGHT+IFjImcEH4DRteg63a76D4MOAJYh/IdYg5rO3xiJOnS1yj1+4wZyUc8uFJV+Y9qCjx20cTD/zA==
X-Received: by 2002:a05:6870:f60e:b0:1ea:989c:3c9f with SMTP id ek14-20020a056870f60e00b001ea989c3c9fmr10853367oab.31.1698077884413;
        Mon, 23 Oct 2023 09:18:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:740c:b0:1dc:797a:dae8 with SMTP id
 nw12-20020a056871740c00b001dc797adae8ls322788oac.0.-pod-prod-01-us; Mon, 23
 Oct 2023 09:18:04 -0700 (PDT)
X-Received: by 2002:a05:6870:b4a1:b0:1ea:282b:288d with SMTP id y33-20020a056870b4a100b001ea282b288dmr13715727oap.37.1698077883827;
        Mon, 23 Oct 2023 09:18:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698077883; cv=none;
        d=google.com; s=arc-20160816;
        b=zlg6nW6PdF/QFQ6kQpxIkhxZv9CZdw3e1geeI6wLw17YVkrHUxG/JwpbK9HECYV1iu
         xRHha9ykmvLez8vBx7UQaH3dI6ic6apGxG8O5WPrsbxaqFzo6k1MCuqNFXOHo6q2agXZ
         yfSTaDT0km3fPjci1tBDYgSuc/M0IaKq9QLza48pin1XU+XeTxCZHJG/P3XuGQxmdFM4
         nABImnScO4EPxfAAiOwK3gRnX57op5aQ3xsxUN2KJhQRkOMXnK/yryWNuMPt8tq2YKhH
         AyD2wtTQOyfQnNCsnHo404cc5lIP/ORTGJHN9CzDni9YwuLE4xZ/aYLtllpEYfE8R46L
         TeQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BPMyERwOm/NcnB3A4LMRfhfW5xHZDfVqvzjxqSuC/ik=;
        fh=ClZrlmqypC8gyPFrg/phNYXzlKrWLi1ezKQD4pdvko4=;
        b=THscPn+I9wQ9w2nScBFRFmseWeY1gKlK9qXXDaba57TT023+Gc/HbURoJ2RRDFq67U
         0F9icdN3H1Y7fGuYTyeLAin9Ts/fRxZTDDEfq01sbZd9lawYXPYDPHaasz6/HQByCrrC
         d/VS9A+/PgyJP4yFLs2IIqiErBECPZ9t6p33fq4dWy24wsB7rC4vKn1XEZ9/9hlj+z/6
         AV6ZtylZCXkagTwIaZiueT5+IxYP+0ZGZXvJAZckGtqsel4X8RDVQlqx/L7jEGlkZpZD
         JxAruJNsXbkvCGUnOW5slD/hQ1Hyo9spXTitc43NmOiDWtkJi6VQGE4kw5se8W8i7QwY
         n5Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Hibmiimk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id f38-20020a05622a1a2600b0041b19567edbsi601929qtb.5.2023.10.23.09.18.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Oct 2023 09:18:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-27cefb5ae1fso2177376a91.3
        for <kasan-dev@googlegroups.com>; Mon, 23 Oct 2023 09:18:03 -0700 (PDT)
X-Received: by 2002:a17:90b:51d0:b0:268:b0b:a084 with SMTP id
 sf16-20020a17090b51d000b002680b0ba084mr7386877pjb.46.1698077882806; Mon, 23
 Oct 2023 09:18:02 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <6e2367e7693aa107f05c649abe06180fff847bb4.1694625260.git.andreyknvl@google.com>
 <CAG_fn=UZu3QpwTQYgXaYe8NVBsuqs8_Ado-+x4pJLaNE+Ph8Mw@mail.gmail.com>
In-Reply-To: <CAG_fn=UZu3QpwTQYgXaYe8NVBsuqs8_Ado-+x4pJLaNE+Ph8Mw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 23 Oct 2023 18:17:51 +0200
Message-ID: <CA+fCnZdGUGd7cAvWVj_Y77W5+CsjguBWB2mQX-Nx4MsYGbVpRw@mail.gmail.com>
Subject: Re: [PATCH v2 19/19] kasan: use stack_depot_put for tag-based modes
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Hibmiimk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032
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

On Mon, Oct 9, 2023 at 2:24=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Wed, Sep 13, 2023 at 7:18=E2=80=AFPM <andrey.konovalov@linux.dev> wrot=
e:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Make tag-based KASAN modes to evict stack traces from the stack depot
> "Make tag-based KASAN modes evict stack traces from the stack depot"
> (without "to")
>
> > Internally, pass STACK_DEPOT_FLAG_GET to stack_depot_save_flags (via
> > kasan_save_stack) to increment the refcount when saving a new entry
> > to stack ring and call stack_depot_put when removing an entry from
> > stack ring.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> (but see the two other comments)
>
> > --- a/mm/kasan/report_tags.c
> > +++ b/mm/kasan/report_tags.c
> > @@ -7,6 +7,7 @@
> >  #include <linux/atomic.h>
> >
> >  #include "kasan.h"
> > +#include "../slab.h"
>
> Why?

This belongs to the previous patch, will fix in v3, thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdGUGd7cAvWVj_Y77W5%2BCsjguBWB2mQX-Nx4MsYGbVpRw%40mail.gm=
ail.com.
