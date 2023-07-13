Return-Path: <kasan-dev+bncBAABBWEVX6SQMGQE42AAKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 96DFF751E02
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 11:58:49 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-bfae0f532e4sf456660276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 02:58:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689242328; cv=pass;
        d=google.com; s=arc-20160816;
        b=N4fnxK+A/9Rs4gZXCNlQw6Y5bI6ouIzOy7o6r1uD3q1llY26+QxhWLgjmsxV6n1qi4
         w/2mpTe0AXNxdNycUBcbo573Fx2QXzVE2OO3G3UxiUbvdWz/UHk1raE46WwXmAioHlYR
         bojygNBrRA93ApCKYjpluCUEQeP4vXcv41DrSa4/g2UjKqT8c+qL4b3ELDxnKS6BIF1M
         ifkZUyNk8JSKpL0dR5x8Xeb4QnozzZ11slgT0jwr+CF5B4D+p/J3LKdHzMo/jUiWNtfi
         MdZzxDRexjs7wwuC9MdCuoo27YERZPOX0WG25vf3RBCRL44FjKDuaUmI9PhK67XIoZQp
         /Lbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=40eOytCa6tH1ZlVSjQrXKGl9Ila+Pa0temxexTBBbqM=;
        fh=fMrwZ6gqbVUwX/RZa95S+UOHvY6rDNQfKRwlXb96bXM=;
        b=MXJvA1Z6wzgOGFmGuaIbqL4lNsoIYCpf/2BqpZCUDqJif97uSvOgw4yusLo141keaj
         bFWVz1ehJeTpem0wnQAWEC2ZA/vq7hxcjppxcpNNhtE+EtLgBblEqkAXl+we86kJsyii
         QqDWsOPX6dkso61DaP+IWv1BuAv20cKUC15nrCBk2pLqLOmiwCKRdfPFl38KR2ZOm3dt
         NLu8JthDpfcE5jpDrZ4PYh2jv0XuBgEAQ2yBVT0CNKYKKNBGTaXTZktFZF2UAYGJ3p5E
         j9EJyNNiMJtjS1zNRAI4+3xhM4N0EeXIAXmWwg33nWz3mRN5PfwiQ1rS11g3jCjI7Xov
         FE2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jHBvHW91;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689242328; x=1691834328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=40eOytCa6tH1ZlVSjQrXKGl9Ila+Pa0temxexTBBbqM=;
        b=XMaHE7WndRotNBRE0IuhV3/8pRk5z2aQurmb7ERM9GSOuUrovB4gWQol1/ddPQkjFp
         rIId6+aN4Zo0S3aCdCyTryLaJKI+lTSfSSdYXp2nA2qbE6YU4Jq2bq+w5/rHhjxgRF+X
         aGdNJnT2Utcu2XIamEQ2jbzDBsVO8Fg61F6MzaUUOPyWxd+sbFEMQIKNoiwYqU1BSGQu
         d8rAg6isCGJkekR/34gOJPKYJjm5JFJBc4gJn7TZi/8TZCLgEEjT5krJF68YTw4KzYwJ
         2SWqc8/AuUq63fUq8FAPspeOfyPpMiO+UozArmMaNoetat6jGHI4GayGrrLI+Bj8iX8R
         wAYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689242328; x=1691834328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=40eOytCa6tH1ZlVSjQrXKGl9Ila+Pa0temxexTBBbqM=;
        b=VdFhNS0AiYjC6ZLSmYRdP93bKCx6Ci6ACn5K7t3mTxZFzeWUEdsKg0Ho6sgJi2wcaD
         oEnmoHTYiI53WvGWosEuRqzgICaJTPDaz3E8Z69y92+iua6tzruoCWtsmdckFr0W70bM
         xzHZFXfKQ1UepwDwv9PxMtGwHkKiIOkee9fbED8o+P6/R+/pkTU3WuC+sWYcTg5HssWC
         QkobAjWp3/MyLyOjD1iUab+n8CIzAU7UMcRNS6LvgtWcF6YNJ0GpspyubgtLaUNopszh
         icziOhrW4DTCOMppRhf12w5xKHpzTW9vcNKpdEQ7X37QnVBrt7RCskQ23b1FNSRzWRO3
         YVLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbHvkwmH2Ddy7qEmUjPNt8NETzsVVqlR5B3Qtak7tzbqVroC16Y
	hB6QxdGYTuI0gswgs3xAK2M=
X-Google-Smtp-Source: APBJJlFWa51AmMzpEhD5iVlHn1m44ddJWcJviZ3Yi6dHqoOE/K7odwFeHik8vSuqDRTWoCzX3nY2+w==
X-Received: by 2002:a25:d42:0:b0:cab:4a58:2535 with SMTP id 63-20020a250d42000000b00cab4a582535mr786111ybn.17.1689242328192;
        Thu, 13 Jul 2023 02:58:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:188e:b0:c4e:81fa:8bd6 with SMTP id
 cj14-20020a056902188e00b00c4e81fa8bd6ls657770ybb.1.-pod-prod-03-us; Thu, 13
 Jul 2023 02:58:47 -0700 (PDT)
X-Received: by 2002:a0d:ebcf:0:b0:56d:43cb:da98 with SMTP id u198-20020a0debcf000000b0056d43cbda98mr1237412ywe.29.1689242327608;
        Thu, 13 Jul 2023 02:58:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689242327; cv=none;
        d=google.com; s=arc-20160816;
        b=wPUYZ48+lY8EYAOfjyZvZ5kY7Iafyhiuv9wq72Y1edrTcTu1o9oD+4IXAZv8epnk2/
         oYztQtO/tnsvisox8bLCStKR9RJIRbgfQ/XbNlkG6xahAdyDM3aCqVCkjutwPp6aUmSa
         HMkuQ5dIXSkZ8nR10chchO+DRp1h/4kFjAgVHCkNPghHIlzvZWUfaG+SGbDWXkkpdyd3
         CVOXbD+jEaKG/rYWDrwCsdn1+L7tnyfVcmvtfGjRup8C7bQBpLHdk7JwbxVp0FzcwqwE
         HJzs3YgQv1woorBsRiwRkMRpUnV0SCIn5V64bBQxPVMP1iWz6fTXiXnaflKkShTZsCY3
         hiqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G709Q+M5XlmXCK/OnlQoWyEQeKVlfPUvyYmmF6WoBRk=;
        fh=fMrwZ6gqbVUwX/RZa95S+UOHvY6rDNQfKRwlXb96bXM=;
        b=pAz8rS1EHMTmCsDe3Mvw7P20kG2l0L2FfJJyvEfsY02OdgRShmX7VBznoxuPgFAyQ7
         uBIBG+YcrQpB7dN/2jCRkwJsBL51Rove7yG5iWpHumvfPgPMSFHR45oD7U39QS4WEDpZ
         PCY9AgggYkYOrIh2jq7Z5DS4l/npBQYnHpEsRdJFgoSOmvqQFZdiUCZdo6ARSU4gGx5t
         ixjrmG4z1HjMlBhlZx1xnkkHvRj30doFQSLwP4RbFYc5keCxko8q1hXZ9WmKyfaH8NuU
         xQyZCxpiKytymGeI3njj5dHDtxM1CiChTfPMr83X+9F8QJNhyIeILZZScXAz8HzP++1z
         M3Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jHBvHW91;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g6-20020a81a906000000b0057a8a1f7570si609697ywh.2.2023.07.13.02.58.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jul 2023 02:58:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2CB8261AF3
	for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 09:58:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7AE6DC433AB
	for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 09:58:45 +0000 (UTC)
Received: by mail-ed1-f44.google.com with SMTP id 4fb4d7f45d1cf-51a52a7d859so3826030a12.0
        for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 02:58:45 -0700 (PDT)
X-Received: by 2002:a17:907:2d23:b0:993:22a2:9234 with SMTP id
 gs35-20020a1709072d2300b0099322a29234mr7118875ejc.31.1689242323659; Thu, 13
 Jul 2023 02:58:43 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
 <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com> <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
In-Reply-To: <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Thu, 13 Jul 2023 17:58:31 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
Message-ID: <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Huacai Chen <chenhuacai@loongson.cn>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jHBvHW91;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Marco,

On Thu, Jul 13, 2023 at 4:12=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org> wrote:
> >
> > Hi, Andrey,
> >
> > On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andreyknvl@g=
mail.com> wrote:
> > > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@loon=
gson.cn> wrote:
> > > >
> > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for memset(=
)/
> > > > memcpy()/memmove() if instrumentation is needed. This is the defaul=
t
> > > > behavior but some archs pass -ffreestanding which implies -fno-buil=
tin,
> > > > and then causes some kasan tests fail. So we remove -ffreestanding =
for
> > > > kasan tests.
> > >
> > > Could you clarify on which architecture you observed tests failures?
> > Observed on LoongArch [1], KASAN for LoongArch was planned to be
> > merged in 6.5, but at the last minute I found some tests fail with
> > GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches are
> > dropped. After some debugging we found the root cause is
> > -ffreestanding.
> [...]
> > > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
>
> It makes sense that if -ffreestanding is added everywhere, that this
> patch fixes the test. Also see:
> https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.com
>
> -ffreestanding implies -fno-builtin, which used to be added to the
> test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).
>
> But ideally, the test doesn't have any special flags to make it pass,
> because ultimately we want the test setup to be as close to other
> normal kernel code.
>
> What this means for LoongArch, is that the test legitimately is
> pointing out an issue: namely that with newer compilers, your current
> KASAN support for LoongArch is failing to detect bad accesses within
> mem*() functions.
>
> The reason newer compilers should emit __asan_mem*() functions and
> replace normal mem*() functions, is that making mem*() functions
> always instrumented is not safe when e.g. called from uninstrumented
> code. One problem is that compilers will happily generate
> memcpy/memset calls themselves for e.g. variable initialization or
> struct copies - and unfortunately -ffreestanding does _not_ prohibit
> compilers from doing so: https://godbolt.org/z/hxGvdo4P9
>
> I would propose 2 options:
>
> 1. Removing -ffreestanding from LoongArch. It is unclear to me why
> this is required. As said above, -ffreestanding does not actually
> prohibit the compiler from generating implicit memset/memcpy. It
> prohibits some other optimizations, but in the kernel, you might even
> want those optimizations if common libcalls are already implemented
> (which they should be?).
>
> 2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
> aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
> you'd have to invert how you currently set up __mem and mem functions:
> the implementation is in __mem*, and mem* functions alias __mem* -or-
> if KASAN is enabled __asan_mem* functions (ifdef
> CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers work as
> well).
>
> If you go with option #2 you are accepting the risk of using
> instrumented mem* functions from uninstrumented files/functions. This
> has been an issue for other architectures. In many cases you might get
> lucky enough that it doesn't cause issues, but that's not guaranteed.
Thank you for your advice, but we should keep -ffreestanding for
LoongArch, even if it may cause failing to detect bad accesses.
Because now the __builtin_memset() assumes hardware supports unaligned
access, which is not the case for Loongson-2K series. If removing
-ffreestanding, Loongson-2K gets a poor performance.

On the other hand, LoongArch is not the only architecture use
-ffreestanding, e.g., MIPS, X86_32, M68K and Xtensa also use, so the
tests should get fixed.

Huacai

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ%3DLKWh4PQ%40mail.gmai=
l.com.
