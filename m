Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVWA5LCQMGQEYUSUDAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id D068DB45185
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 10:33:27 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-71fe8dd89c6sf35171006d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 01:33:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757061206; cv=pass;
        d=google.com; s=arc-20240605;
        b=R14HfkhnnoZEcJBL71PA9cs1byxaubc5OPEYqc0TFD4dMC2YjMmB12n/slXhGD4j5+
         IhLLeyseXS7ADwEpgaSqHdax8LyCDwl35om34ldr+t5JRZG19KQrZtduHtQ8VZtgC6yS
         vTvJMbsG8B5FbfCEoJE/Rq5DIARrAvJKTrWtVA90RO1o9fq3+OLIF2nWyREu962N0deX
         c3wE72Bfnp6xucucXmmBIG1RkgYCw/2SJOZW1PRzIN7DF4hQw3JF//taK+MjrpA190RR
         4CnnYXCLolkn4+Xs2yzu2sGRDSlr1R4i+eWS1tbugmNAtZRoOnEtK8FLaeyky0pEJrdJ
         s+3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Heb6mNM/tcOOClyvzyXoVwShB/fwwbgy5PqcKRgzI38=;
        fh=ReFN+TkJSJSfpBbbLLodLoo0LiQ/NHIanZMvpUotGuY=;
        b=BzUFwt8SiyFfVb1lsGMoUm+rHU9l1fowe95j973VC1u2u02BcmPuFWiFv6wiFY5zEe
         wJLOBpOYhBRQGNt7LzI919h2qZ9vmt53FYrmCW3ypW6yRmXqV7OzlvXbJVzSxk+GOoaO
         BB9mE6bRPJ+uVSYwuNIyi9ijjD4Vs5FxjQt6V8TrCbbf0JhTqzzWoJwN5HtZ8Z5jogaj
         ttKRc+dQ5L/hPxcCs/2ZdSFwDdMnT3IFDvJ/GJYvW/gueyckJR/M5ZGC8ijerctCNTTn
         iMOLSh+TkXn0DCeTSuVS9z4SVgjEnlPcQavxt/zZzzwMINPki7CMv/9fBlNiQ+JjYsKE
         p1IQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ko8Y1617;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757061206; x=1757666006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Heb6mNM/tcOOClyvzyXoVwShB/fwwbgy5PqcKRgzI38=;
        b=VfyGNTNm+u3j9gv+4MS6vsNTOdad+3LlkiWLE9VKqouL2dd+5yq+ZUEGVtdq5HN6Nh
         lJ+AmkktPLICnxibDpL4ZDMukMDUV/sqEYjqbARSfSXsjobVfAbmqIX88wTvP/X2S1OL
         +41YhGKt7MharSveklxeixk6iVG3csU2uBnOSeGXiAbXnNjgOwNtmDeOk07iuNbWYdRv
         flAqxRyAPSmqgS5tkBOrPcXlPtUAnllPGtdJ4TJso8frG8Vn1OmUN2aGqKfjEfIXylRi
         e4A6bTuQdp1Al7zfK8Oqf+bL9D6Dv8nzq723tOHzDHNAb7h/QFilprsTQXTwm6UnTab4
         zuVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757061206; x=1757666006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Heb6mNM/tcOOClyvzyXoVwShB/fwwbgy5PqcKRgzI38=;
        b=gPp6jNg/scEuZ7Kyvxs+d7cOBv7Q1ySoESczP1Mn/vtVVMjEKE/iS+YK1qZOkR7dgP
         n9mW9OquBmAB+zUOCTskg9ZrXuUY53NuWNrQhP/1vKXC/txQTeow7JLKH6we2Vq4dCPr
         qeyGA6gn8MIhDHOYov5BGwmRWAoy1EvfCGw5UUwNerHKRPjNEQpND2bkTLuJk+vL2xzF
         7yMUbt/OX+wpLaLPmmA5gKlrKRwTm1OO5e840CMUnZhTpym4+zau9BRbrR9MxV12tYA8
         yEOTxFWP04Ppt6VL1Tq6C6ZE8x1bwn/fzintvo+WGoqwDb1KkahUmYN9QlGeBhksK0Wu
         c51Q==
X-Forwarded-Encrypted: i=2; AJvYcCVouy+W8Yu7gWnq3A17gVwSnV+LVA4hXGmlkfZ7Y+EF0dsVUYP8/+0OiPQefut1LeLTp2/0+w==@lfdr.de
X-Gm-Message-State: AOJu0YwS2HwUHJ7ChcFvKSae1mBpBGxO8P2ImHqnywmKYwfGir16jhMD
	Va35jsAzaL/1tNJBFoNRUGh8wUMYGERbHoMscDgUmZ18FGXNGTTi7cii
X-Google-Smtp-Source: AGHT+IEb17bmLL9jsPAthI9D4p+LL4DtZyAgSLePSGiJKIyb48ZNc5JQkJ5bUy9iNnWL5abKZ6Nj3w==
X-Received: by 2002:a05:6214:2e85:b0:722:25e8:b488 with SMTP id 6a1803df08f44-72225e8c257mr93229886d6.27.1757061206419;
        Fri, 05 Sep 2025 01:33:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfjgRDTTO9CCA4QzuMNSymh5TznBy8LyEU63WTPwer+jg==
Received: by 2002:ad4:5be9:0:b0:70d:e7ba:ea21 with SMTP id 6a1803df08f44-72d3934a1a4ls6317946d6.1.-pod-prod-09-us;
 Fri, 05 Sep 2025 01:33:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcjK5sOmRMGZwd6hfclSBshO2lp/ibE2I87I5qrQWiNnERAYOx4DebbUmAgCYGQQqnG2VER1sZsNY=@googlegroups.com
X-Received: by 2002:a05:6122:4687:b0:541:53a0:823 with SMTP id 71dfb90a1353d-544a02e64f1mr7284882e0c.13.1757061204983;
        Fri, 05 Sep 2025 01:33:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757061204; cv=none;
        d=google.com; s=arc-20240605;
        b=dLEWvDQeUWH7XtKkFOcq7TTl28THg3MPO3VuY8lrquHW6NKXr4SJmXZWwoCcLsfED5
         OjaUK027tqF5Gdq7U1aRFHRz2EIodG8fhEL9Z5mLfPkdRi0jnaAd9lngDLj2LBy4Up0s
         hjtX0tImCV8HnqhI/2Gh9xDFDs8l3NFiq7US191exh38OlfkyIBeWpbwIde6LIVsztDs
         LO/WFNCaCNvwVfC05zFIsYDOCDMGE3jtIRSnPhL6fRBs2jNurIEShUQb5BUDOKt2tqZW
         BzZ//8et+2Ib0zimRsZ2KY9OK+69bwOmMwNjdKfZDXhurRdI9BrFrhQ+z+G0oVcGoTv8
         oq2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NiGQFhCM+75MKVgSkB143RjF35qXTjKYNYENw01ZAOY=;
        fh=N0q9XM2ezEa2E7YyPTFJeMaCXJkWs7nV4Z8+B5+diYQ=;
        b=SndKqHmxb33XTb2rgGqQZ1lI5WdUq7VcpNkO7BxPqLhV0bQpYaIjyxN+zt6rjEsPNu
         ZMiWKYSUEg9zKvQgXyQQQHcyaa+zkLq20zZ1H0XAYOLUnHW35hKq/Vshw/kEJdUJo3NE
         +tiLJwmopCzIN1+M7d5r7TcRvE7yj8uo3l1fYgoYTQ0DDCy5Fylpp86YLYYq+4VjMzwT
         qfrVtqrV0uF1W3sB3MFc445WBycLGOvBBPVnQpAK1eYEWwm7sflJ39PyjLuPRAZr7LND
         DgZGYl1u717KIXGp1WN15MqveflQ7Xodtjqet5RnQ182E+ycUk4e8AMdeTtsxekcUp76
         bWLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ko8Y1617;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544910f5312si804824e0c.0.2025.09.05.01.33.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 01:33:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-726dec342bbso18664276d6.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 01:33:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIy71fYfBxLniQmE88SwmzsDw0Kqm/eFNzAmQKKclxfHYX48JfgpiG+m0Re5tQyipU/deJCWwIi6w=@googlegroups.com
X-Gm-Gg: ASbGncuHIIlONP6qZoaiB5wDyG9HmmKIsDbUJtLPM+b3dfeVCsKrO9bnPKKNlKNAIf0
	0JWjE+jAUEjpm/q4A5fXoRaepfNf5fAGVzsIyZ9OJqcCcRra+lGLpJywUi2suCBbe9zKpgkt8G7
	iIrJriooHAT5twVDXheTL/pFC39xx+BrDnnvBj+4BKT/OupnAPXIYDKenK4vtrtD4D0i0UQzY7P
	n4qWyATUaWBxGlebPD9lxBgumahlkmPR0Cs0kGC60L+
X-Received: by 2002:ad4:5c8d:0:b0:729:4be4:7fdb with SMTP id
 6a1803df08f44-7294be484d2mr55718806d6.52.1757061204289; Fri, 05 Sep 2025
 01:33:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-2-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-2-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Sep 2025 10:32:46 +0200
X-Gm-Features: Ac12FXwF_nrqiRF1QRwe4SEL1LOgGhI7gT4sYUe3e0eDMXNCPS7Bt_KSLOk4LK4
Message-ID: <CAG_fn=UfKBSxgcNp5dB3DDoNAnCpDbYoV8HC4BhS7LbgQSpwQw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 1/7] mm/kasan: implement kasan_poison_range
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ko8Y1617;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 1, 2025 at 6:43=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmail=
.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Introduce a new helper function, kasan_poison_range(), to encapsulate
> the logic for poisoning an arbitrary memory range of a given size, and
> expose it publically in <include/linux/kasan.h>.
>
> This is a preparatory change for the upcoming KFuzzTest patches, which
> requires the ability to poison the inter-region padding in its input
> buffers.
>
> No functional change to any other subsystem is intended by this commit.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
> ---
>  include/linux/kasan.h | 16 ++++++++++++++++
>  mm/kasan/shadow.c     | 31 +++++++++++++++++++++++++++++++
>  2 files changed, 47 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..09baeb6c9f4d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -102,6 +102,21 @@ static inline bool kasan_has_integrated_init(void)
>  }
>
>  #ifdef CONFIG_KASAN
> +
> +/**
> + * kasan_poison_range - poison the memory range [start, start + size)
> + *
> + * The exact behavior is subject to alignment with KASAN_GRANULE_SIZE, d=
efined
> + * in <mm/kasan/kasan.h>.
> + *
> + * - If @start is unaligned, the initial partial granule at the beginnin=
g
> + *     of the range is only poisoned if CONFIG_KASAN_GENERIC is enabled.

Nit: for consistency with other functions in this header, can we
change @start to @addr?

> + * - The poisoning of the range only extends up to the last full granule=
 before
> + *     the end of the range. Any remaining bytes in a final partial gran=
ule are
> + *     ignored.

Maybe we should require that the end of the range is aligned, as we do
for e.g. kasan_unpoison()?
Are there cases in which we want to call it for non-aligned addresses?

>
> +void kasan_poison_range(const void *start, size_t size)
> +{
> +       void *end =3D (char *)start + size;

There's only a single use of `end` below, so maybe drop this variable
altogether?

> +       uintptr_t start_addr =3D (uintptr_t)start;
> +       uintptr_t head_granule_start;
> +       uintptr_t poison_body_start;
> +       uintptr_t poison_body_end;
> +       size_t head_prefix_size;
> +       uintptr_t end_addr;
> +
> +       end_addr =3D ALIGN_DOWN((uintptr_t)end, KASAN_GRANULE_SIZE);

I suggest making it
       end_addr =3D ALIGN_DOWN((uintptr_t)start + size, KASAN_GRANULE_SIZE)=
;
instead.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DUfKBSxgcNp5dB3DDoNAnCpDbYoV8HC4BhS7LbgQSpwQw%40mail.gmail.com.
