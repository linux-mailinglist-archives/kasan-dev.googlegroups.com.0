Return-Path: <kasan-dev+bncBDW2JDUY5AORB5XJWS2QMGQES7TU5VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 481E69463F7
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 21:35:20 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-52efe4c2372sf9748895e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 12:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722627319; cv=pass;
        d=google.com; s=arc-20160816;
        b=bVMwLlpj2KqCZtaKzVzsQl3AEvp9yGM1HxeyZDLTfxL6kcHHpX/0oUXT8VCjClMRaA
         PBim77lM2rGqofwLJGwTG9UBWQpzzEyxl2UO9alOBbfkrgOSeQ5HRs+m/dEvh5y02iNf
         Z7Be5zpeJ80be4Ib0P+nrY2ii7ZI5VGqhx0dq92kDYA1ySYMTx0FTjy8ZzrfpHSYx+Gi
         R8poxJDc2+eviGH3dKAhx2P6MQxrGJrrzEE00rqJbNG3xasEX+zGQwRSwGfIrr/QfuEc
         NmI9n/DZA1yx0PWuOf2tWh3MlSDZ62r/bnRTf++bE22GA0q5UM2u5jxEATimvxrriyB2
         AyJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ZvZ+yjVVS0xSQLUUX5TGq0n8qKmLafmgzDPRlPvdnvQ=;
        fh=QCBi/OE2J+RB+kc98VF2gDTatmGFoid6iHWLMPGeVlk=;
        b=siS+p8pBGKyGa222wSqJHrHdjXh6aYu7lMbYRzjNpewZn/1pYV8aJrWHB20udNsKrb
         fQYQinYcRGsUNH9aHHgWuKKIkyQRK9jEB2yNW8RpvgVZNQlsIZaJ6j/ugNjevCnvbVqL
         xg9nC6ArrGdZWTYY5MV3ZMd1tq74Fhay1k74mvzVYFEs8yfPOtJDvX6at9B7FGjqOkPd
         m5I80FbfhDIQnpk97zysV6qLRmj26c88cMZTvOjicCbAatcMAOUHWPA3jz2JbF6fuswa
         jkPxyT7CoQ+F0R7WN/2Ejcnw5Tz01onKWkOBCR1TmvKEgruwmRUixAWikiB3cE58LlWV
         s15g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KGCTvfCV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722627319; x=1723232119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZvZ+yjVVS0xSQLUUX5TGq0n8qKmLafmgzDPRlPvdnvQ=;
        b=KjXBIhl3hq2kM9JXWhCXib/c9v8JgUZ+SttMbsk12ymGraAiRWZWfQtwbJzROx/VFW
         xFuu9NwuctuLMPCcPrXx06UU3NHR4WXIy3BzPuuvc3K4a8p/92RlYNmFMwAOu00DSU55
         +UmfgB2dOxq9AKGRDtgMPoMo/aFfMW8oQLqQ2Gp6zY7tNVgNgf7wQ2hRtw/1DOvXF5e+
         8W0P3msC3hEw2esMhi88Q3l5siWZViQiVVpt/SMkemVdrnSmiikYIQI9GS/BsuSPf1Po
         h8t3KcPsPno1+HgnjyKlUavC3XLw90aFqj7TD9TZKNHMtnRd2KZjNqxv+/KpBOKEcRry
         gT6g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722627319; x=1723232119; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZvZ+yjVVS0xSQLUUX5TGq0n8qKmLafmgzDPRlPvdnvQ=;
        b=lp0mg8FjdSeZFnjfHCNI9WGeO41kecZzbMCqZHxYom4FoOgl8XDPdJGY2272PNABVw
         PeGL7LgxkaPDop5iu2+lkjc4hYsGzn+XRfPUgGTZZq8KYOSe4RWJc5pX/2kC/YmIcmHh
         09TkOlg43v6A8MNsi7LCWcSSxZuopDd9ubhys7VSvH5J4zvc+TR2WL4plpq+MohNc4om
         fO2F1DCBo0Ezl6U3+f5+S03bISYLLLXXbbToCv2bX5Q46lxnRNjKEYzSJIKQpgVBY4fC
         OWRK9cgzvRcHs6NRgWorw45y8DUJzGzdQWDVTWYaB9KTYTVU6c7Zs6e7PQpSIKImLGkQ
         FyNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722627319; x=1723232119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZvZ+yjVVS0xSQLUUX5TGq0n8qKmLafmgzDPRlPvdnvQ=;
        b=mRQtWApwSZux6B6jNnJnp4Bn1zlKPrrW5SyfmAqHtw3UxIpeWOBLHAIPW9r8sR1xm3
         DcvSG1WOSd4U8ZvuFHgeV21X+UW3AFT1FUnCxPFU/PJ3Q0y0R6jEIIFuB9kcM5jcm55i
         vW4fy1uOkXe6dYFygeMWOOcTGXMt4yJs5l/55folNRbpGEmeOS4Xzw8F0L7WdSkne3DF
         4jY/kdny9IZRVkCEB2jcMshC/2fMigjLppR4LubXMGdQ0fbZ9CdanM8C1kFBvRHjC4kA
         pgQpM4iw/847CYNqkK9PHBzL39xc1P0LmmFjSG1rwK55PlM0XI2OIFIkvYe2oziCa5ag
         ScnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVR6tqpN/HmTggtjGoJFvtgjUZjbFd4Zpxlc5IRejur2hsUMigzhbp/Y6I3FSLPgMSeZuE9ad4asqaH7SP9/rvnyIrFWE/1ew==
X-Gm-Message-State: AOJu0YxEjZsE3KCRBMdshwE/OOGj70NBlmzv32w/j8a3l5qLXUNfC+9a
	0D+mSgc9otq9/MOkNklxz+KgQ8FYbqz4sg8Pa6+ge4DsBtqkjWtN
X-Google-Smtp-Source: AGHT+IEAD984UAeCkVcyCngA1ogtm+evEVp9P130i02J1kWEL4ftFCRs4LC8vpi61m8bNnAbevivLw==
X-Received: by 2002:a05:6512:ba9:b0:52e:9481:eaa1 with SMTP id 2adb3069b0e04-530bb37425dmr2934911e87.23.1722627318789;
        Fri, 02 Aug 2024 12:35:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a82:b0:52f:c300:1e33 with SMTP id
 2adb3069b0e04-530c31f1d1dls117988e87.1.-pod-prod-08-eu; Fri, 02 Aug 2024
 12:35:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUH4+pVAQzjT7q2rT8bbu/x08mbcp1rSnFUHKlyU4uMv8JviXuEOzgZEUMpY93rPNRZmuC8pnHEIsIDbmk5SrSXfOllH3IXvg/xHw==
X-Received: by 2002:a2e:8747:0:b0:2ef:22bc:6fb0 with SMTP id 38308e7fff4ca-2f15ab01385mr29964421fa.34.1722627316686;
        Fri, 02 Aug 2024 12:35:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722627316; cv=none;
        d=google.com; s=arc-20160816;
        b=0DYBr0s1Jp9I36ao1CCKpvt0KwWb94pR0tmbix0xKflS+CfnxyWTkpCmsHEg0cBr1r
         LCxX2A+xOdLDTU0EPrXHsozmErYsuyx1VdHyD5JjH5wX7qbq+apoFYfUu8QH97xKYdZQ
         5bZgN0+mI4MxeV7uwwpjdedzb1Isq6NoEc3w3R7HGgM8CcRdAu4ejREQ8+6GGuTkulsB
         +AlmRrkkiebKFLTlW4WWWWQyjxf8P8sP2mZJnakBiIXEbKspMgsC5nwZFE1qW+BJQ04P
         SIVUFHOxGGIODOWakijI7quZjI+FYaWPoB3JhIjkhXMbExM4Oesf5j3Dq9nMTpqd5zq3
         komw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5oLiqaitihQSNXgz5f78HG44TyzFMAf/LHbh+J7eSpw=;
        fh=fOFwmpMWtZOn71ZYov101WKdG5sCjr1fSeUNhjLQNyk=;
        b=AgxeCpdom1yUR4SuVc29t8gZV42q/yjSkCNq8T6+bkxstKe84a9hhkzHsp5cpp8KFj
         5LtLowB5eSRd/SukEJu5/2oCRXbRGmsGo/aGx+XkbyR1h/WbpGNTMe67f8jx3lsX1iXG
         cYqQ7L2xBjRKaGXUMzAn9w03dETp8Vxs0Ej3+cE4NnaYBJzLDwPvyTzpVyhlpTaX+vkC
         pra57sUbr02Nqlq4pfW8xTT3i2QhOmUv6J/yhGTTphhcWq/w494mSWvwLqZehd5lA+bI
         /zASHQgfuVnWXArSMkNbrFxDkZ6ys2z4OYu3y8+KzJhX79quD9DmunxE1uj0XpwuVKKf
         Z4wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KGCTvfCV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36bbd6f84d8si52319f8f.0.2024.08.02.12.35.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 12:35:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3684407b2deso4320375f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 12:35:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVv52Wp6XKVQ6LsQz6loJ6mmoYJn09uGPSaFLZvENGy5yMn+yD2RYGKncsLpsUhWoCV1qPIXp+2+4qIRqA6kU/fabsHV/XgGaJX4Q==
X-Received: by 2002:a5d:508c:0:b0:366:ebd1:3bc1 with SMTP id
 ffacd0b85a97d-36bbc0a8493mr2388276f8f.3.1722627315779; Fri, 02 Aug 2024
 12:35:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com> <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
 <CAG48ez0frEi5As0sJdMk1rfpnKRqNo=b7fF77Zf0cBHTFO_bjQ@mail.gmail.com>
In-Reply-To: <CAG48ez0frEi5As0sJdMk1rfpnKRqNo=b7fF77Zf0cBHTFO_bjQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 2 Aug 2024 21:35:04 +0200
Message-ID: <CA+fCnZc1HSSD0eNgg=KXGPOspmYHLbEExPHZASJ45AXSM1L83A@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KGCTvfCV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Aug 2, 2024 at 11:57=E2=80=AFAM Jann Horn <jannh@google.com> wrote:
>
> >
> > Let's reword this to:
> >
> > kasan_slab_pre_free - Check whether freeing a slab object is safe.
> > @object: Object to be freed.
> >
> > This function checks whether freeing the given object is safe. It
> > performs checks to detect double-free and invalid-free bugs and
> > reports them.
> >
> > This function is intended only for use by the slab allocator.
> >
> > @Return true if freeing the object is not safe; false otherwise.
>
> Ack, will apply this for v6. But I'll replace "not safe" with
> "unsafe", and change "It performs checks to detect double-free and
> invalid-free bugs and reports them" to "It may check for double-free
> and invalid-free bugs and report them.", since KASAN only sometimes
> performs such checks (depending on CONFIG_KASAN, kasan_enabled(),
> kasan_arch_is_ready(), and so on).

Ok!

> > kasan_slab_free - Poison, initialize, and quarantine a slab object.
> > @object: Object to be freed.
> > @init: Whether to initialize the object.
> >
> > This function poisons a slab object and saves a free stack trace for
> > it, except for SLAB_TYPESAFE_BY_RCU caches.
> >
> > For KASAN modes that have integrated memory initialization
> > (kasan_has_integrated_init() =3D=3D true), this function also initializ=
es
> > the object's memory. For other modes, the @init argument is ignored.
>
> As an aside: Is this actually reliably true? It would be false for
> kfence objects, but luckily we can't actually get kfence objects
> passed to this function (which I guess maybe we should maybe document
> here as part of the API). It would also be wrong if
> __kasan_slab_free() can be reached while kasan_arch_is_ready() is
> false, which I guess would happen if you ran a CONFIG_KASAN=3Dy kernel
> on a powerpc machine without radix or something like that?
>
> (And similarly I wonder if the check of kasan_has_integrated_init() in
> slab_post_alloc_hook() is racy, but I haven't checked in which phase
> of boot KASAN is enabled for HWASAN.)
>
> But I guess that's out of scope for this series.

Yeah, valid concerns. Documenting all of them is definitely too much, thoug=
h.

> > For the Generic mode, this function might also quarantine the object.
> > When this happens, KASAN will defer freeing the object to a later
> > stage and handle it internally then. The return value indicates
> > whether the object was quarantined.
> >
> > This function is intended only for use by the slab allocator.
> >
> > @Return true if KASAN quarantined the object; false otherwise.
>
> Same thing as I wrote on patch 2/2: To me this seems like too much
> implementation detail for the documentation of an API between
> components of the kernel? I agree that the meaning of the "init"
> argument is important to document here, and it should be documented
> that the hook can take ownership of the object (and I guess it's fine
> to mention that this is for quarantine purposes), but I would leave
> out details about differences in behavior between KASAN modes.
> Basically my heuristic here is that in my opinion, this header comment
> should mostly describe as much of the function as SLUB has to know to
> properly use it.
>
> So I'd do something like:
>
> <<<
> kasan_slab_free - Poison, initialize, and quarantine a slab object.
> @object: Object to be freed.
> @init: Whether to initialize the object.
>
> This function informs that a slab object has been freed and is not
> supposed to be accessed anymore, except for objects in
> SLAB_TYPESAFE_BY_RCU caches.
>
> For KASAN modes that have integrated memory initialization
> (kasan_has_integrated_init() =3D=3D true), this function also initializes
> the object's memory. For other modes, the @init argument is ignored.
>
> This function might also take ownership of the object to quarantine it.
> When this happens, KASAN will defer freeing the object to a later
> stage and handle it internally until then. The return value indicates
> whether KASAN took ownership of the object.
>
> This function is intended only for use by the slab allocator.
>
> @Return true if KASAN took ownership of the object; false otherwise.
> >>>

Looks good to me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc1HSSD0eNgg%3DKXGPOspmYHLbEExPHZASJ45AXSM1L83A%40mail.gm=
ail.com.
