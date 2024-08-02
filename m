Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPX3WK2QMGQEYVLNQJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id EBC7F945CCC
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 13:06:39 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ef23ec8dcesf79889621fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 04:06:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722596799; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZfF/vizO2OoeIK6EALs9geNF8nGM5dd26W7FZUqElDJdtoO2E+wLoxqiTtsLWFH9c1
         LkKIOSGaH6q5qo8tUg9nNTRvIX5SezmuUADpDIvEPcWzHbvZGY056YA+u6vv3SwyKfNP
         UWd7C2ygWqgdSU0I4jM0djco5le3RMj0hGjN5nPOojfEEqX1d62Q+CebM4tjVoKNIGZp
         SZBsv4fleytre0hv/KNzwMRj6n4uh6rFgTY6KfWEvpuZENv6vvEvRjclCXNujJ5Jkr6E
         60L24PpkWgFPR+0/oRsksoufbEw1dd0rVdmegYY0f7kG7Gc8CL2kG2qUCmcBkw0/P8eq
         lOoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f8orbr3h7FAaOQ/raFbd4ehD/9BTYAdXQAYmgSzwlDA=;
        fh=qefp4U/kiVJjaNIC4D7e8uWQlglMO8Wzo6Fjq0RW4/s=;
        b=N+yjTUqb8Vd4ZKPgxC2LiIfGVenSnnvEigDmUhdBDTGKflSYCIepOGuz+W3sxzyIB5
         FQXEDllF6zNPGPJFyV4zw7bfHDBW2LCIPSneQdbwDcqoeMI/0HyBCKEBkFHocD9FgpsP
         jJWS7T02HEa/SLSRN+kaMnSQ1QCorbcDMKfSPaTurK5ysQbvfKP5ZlxlCsdTacjKTVua
         ooNIkgkj/MwvAjjTjwbQJlo66oVKj8Ojy/ULyNW730nQlc47krXbAwRyal8hZtHv8bXN
         4J3QndPDaC3nzE9iAxWSkwKwbU6hJoBB4xKXN8MoBAqMktW8bSoVHPG0TowAmgV/NAnJ
         pxHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KN2EElZQ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722596799; x=1723201599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f8orbr3h7FAaOQ/raFbd4ehD/9BTYAdXQAYmgSzwlDA=;
        b=O5Wo4cACh6q39pYi5STTFzp9tW1Q/wNmandIllT+aAgtlZVsFNb48LGOIrHEngWATr
         rlVYncUScPxWMKbDQ8sfFEpxbm57dK94qIYSk4hgGYPXXCkxjb3mQu3Zd/rJYmY7AqzQ
         AG4/b4cCZLoxQtFlle8EGpa24ISwvZIlBRygJX7ypfwLSR0xmCV1sfpCn55V8/THLD82
         HPwKkjHfhDYhvYXCzwM3VYh4SdpziDu59i+/dl8sRkZkc/u0niVGTkD+hTLPYtbaz7Pj
         DISfdY4ns1cie+M9KI5CnUsbPtwGfB3Dt/2XZFW8/wcei52NzspP9DKPJCx9/3xbEGQ1
         9cXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722596799; x=1723201599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f8orbr3h7FAaOQ/raFbd4ehD/9BTYAdXQAYmgSzwlDA=;
        b=tCD93/Ygnc7x0/+GSUP2Kt3CtZoljmFV2RLYnOUE3UMtWFEkDDVAv5MXXWazbRIf86
         hbMdNqqZzWPXfklX9+1F1p7WQEdKMdc3GILRBgT3qiSD/BnCUGeSm+cWcrtTmz0sTFbr
         gqXgQl+CzGWi7iTJaPInetbBGwB+6682maYb2sACm68a/6MzC/NvcTs+YW9QDsqmG2FA
         zd1q0XupPzboIpvlSqOHd8bEkerrjXEP2kU/H745HFt6nG0yzHek1UiqfavkpKcZRd6O
         OmaDKyldpNwT7T3tmvdMuNSH0JHJY/zXB3cA4dqK9xzKqMdyhPg84ChmuOXexFOz/jpn
         9w6Q==
X-Forwarded-Encrypted: i=2; AJvYcCXNzxWicRbYp1FKMShvayk6FOH8Lvgkl1ChZhkC/h62tja/XSyQJ0H7goSAwCRaPUeN/Ybc6LzqbAPb2gRrWleZvap3jupo+A==
X-Gm-Message-State: AOJu0YwNJ+XphOPubvby6f4MBVhLH2F8MTboLJNHG2vs6DNZL3+L6soX
	ebHBG17KxBF9Q+6OBZfeQUwaRMvWQBa7HPw7NkfY2Ay47KzTyybI
X-Google-Smtp-Source: AGHT+IG4GkNeTE/gFwrUt64fz1Q/SVFBdlWaYLPmLXug5D2oueu/HUJ9bSjhfLiSBzfiuEgrGJuCRA==
X-Received: by 2002:a2e:9b88:0:b0:2ef:1b93:d2b6 with SMTP id 38308e7fff4ca-2f15aa84f34mr22234241fa.8.1722596798624;
        Fri, 02 Aug 2024 04:06:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a99d:0:b0:2ef:2eec:504f with SMTP id 38308e7fff4ca-2f03aa79f40ls33462411fa.1.-pod-prod-07-eu;
 Fri, 02 Aug 2024 04:06:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8A8rWwVyfD1gJI/QYRfmF1lL2LLtmQHKl+yGQRnbcA/HWYToR5XBs7PpUM5+JJVH0U+qzQtyMxrfEcKm3LGYVeCtn6HaMIj7uDQ==
X-Received: by 2002:a2e:94c2:0:b0:2ef:296d:1dda with SMTP id 38308e7fff4ca-2f15aa84f1dmr21903291fa.1.1722596796110;
        Fri, 02 Aug 2024 04:06:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722596796; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8D6dzYl7I7R8LOOX/v7eVZMuMaMdZp58vLem1GMKV+FZpC9yewWfDB7a1/+UlUKDt
         p7rPzUkCTPgekWe66RLCUUr0cBjKv3f5CviuVQxbiZDdLhkVd9wdFWA6EDWLhDzxVDmn
         M19Vg+BCH8jbsSaLpXZdNP1duUOzc1gyy5Iy43f4u3UJUUPv2e+UscaxHas8LoCydLgn
         BIlHWmRVLy4toxmLD3VGYYShbWqy+rMI91gktjvNSwRqYCASVF6HTnLApjKGmxm5kPRH
         6qUmW4PUJwQgz0uZ4FBWSlGy3yrfNKA/QqWjQOk26i614Akz89JI4q2oy1PA1yhu85Xu
         uPjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KRR6BpufkDTMSbKYLs5P5x4tc4mghVB2+YjYQfPNLdg=;
        fh=DmuOMkZ/Nk/g8A9P79Y/q+6/0rdx+FuYCjxkPDXyda4=;
        b=VptDsv3UJHs45W0ReNbu7hvnGbZdQQV299KWegfoLZUy2VJF+ow22zPqiM1iEP86Bd
         jUL7Xj6iVDw5KhdyAdhWGMDk3S4dPx8A85imDSOgqQYqeeF8iOW6+58IErNkpZHSicj3
         A5ez0aS4rBxxJ/QtFpPlDrl9LTTdTTGz0NhTEFpAbpPjCN7x3tkyX93L6WZ1BZERAT11
         ZGVjUiG0NT0G8bjqlaxKAwwEzv/uOoR7JWTvct7lIVOtkWS5aAyxpGaZF6yLYAA83gWr
         23X4UpxHBlxIACIIhBAS+sQJaI6rSWms+E8hArNJ12XMczoyiaf4pV6lIv1nbqbFnJnl
         hkjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KN2EElZQ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e291dbasi294921fa.7.2024.08.02.04.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 04:06:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso50795a12.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 04:06:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUPTZ7lstazAgJxQefG2dP6fdc0uDjxiCpbUFgZrkcyGsOmXYjWrRoXpMA1Ffer1uGoXV3R4HyJgkKQoyrzRX/8R1Hz5M08aEME0Q==
X-Received: by 2002:a05:6402:5206:b0:58b:90c6:c59e with SMTP id
 4fb4d7f45d1cf-5b8713605e3mr112092a12.7.1722596794707; Fri, 02 Aug 2024
 04:06:34 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com> <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
 <CAG48ez12CMh2wM90EjF45+qvtRB41eq0Nms9ykRuf5-n7iBevg@mail.gmail.com> <CA+fCnZf++VKo-VKYTJsuiYeP9LJoxHdd3nk1DL+tZP1TOQ9xrw@mail.gmail.com>
In-Reply-To: <CA+fCnZf++VKo-VKYTJsuiYeP9LJoxHdd3nk1DL+tZP1TOQ9xrw@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 13:05:58 +0200
Message-ID: <CAG48ez0NZYOwafGfXw6pN91zeFH60CSdeQrTLgJffrbu1xPTBA@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KN2EElZQ;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52f as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Aug 1, 2024 at 2:54=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
> On Thu, Aug 1, 2024 at 6:01=E2=80=AFAM Jann Horn <jannh@google.com> wrote=
:
> >
> > > > @@ -503,15 +509,22 @@ bool __kasan_mempool_poison_object(void *ptr,=
 unsigned long ip)
> > > >                 kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FRE=
E, false);
> > > >                 return true;
> > > >         }
> > > >
> > > >         if (is_kfence_address(ptr))
> > > >                 return false;
> > > > +       if (!kasan_arch_is_ready())
> > > > +               return true;
> > >
> > > Hm, I think we had a bug here: the function should return true in bot=
h
> > > cases. This seems reasonable: if KASAN is not checking the object, th=
e
> > > caller can do whatever they want with it.
> >
> > But if the object is a kfence allocation, we maybe do want the caller
> > to free it quickly so that kfence can catch potential UAF access? So
> > "return false" in that case seems appropriate.
>
> Return false would mean: allocation is buggy, do not use it and do not
> free it (note that the return value meaning here is inverse compared
> to the newly added check_slab_allocation()). And this doesn't seem
> like something we want for KFENCE-managed objects. But regardless of
> the return value here, the callers tend not to free these allocations
> to the slab allocator, that's the point of mempools. So KFENCE won't
> catch a UAF either way.

Oooh, right, I misunderstood the semantics of the function. I'll
change it in v6.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0NZYOwafGfXw6pN91zeFH60CSdeQrTLgJffrbu1xPTBA%40mail.gmail.=
com.
