Return-Path: <kasan-dev+bncBDAOJ6534YNBBGFX73BQMGQEV3BPI2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE86B0DD20
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 16:09:30 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32e157ad381sf27350901fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 07:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753193369; cv=pass;
        d=google.com; s=arc-20240605;
        b=OphjSsLm7fQ5Irssh1mx1MyXLEar2LuJ+dsWrC6MvVf7wGpwAgXOi3GwNe1PSqMtK/
         obeheQfCYBDcP6zJBAyjXLBwiGK6w1qBakLy4hZq8NjThz6q8LkcBfzR6tBo7KStzyXt
         sb6yRMRcSQq9VfQGIMH+T58HTUcj6LAaK4CdDCvaFfo7UiQRL2641WD3PTOAP5mBShO3
         1HWeTSfSj6P8ErECZ0yczyqM0tdBK/r/gRA6xbOYf33/wRGD8/iz6ExgkV55BD2Qi5eq
         L6f0dU5JSIf7jL6S7iNLVrKoNPTZCQahtd/T3FbknzLhv2g8Si6aDZrUgmQXqBaigVhU
         Zl3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Poy4bKsx8eR5468CsaTfzRZUNt4KSo08NHb4ysrnS2A=;
        fh=nbg15Ty1ektEjgKlT0ZreCYfFJgzC6tCiQrA09Q8waA=;
        b=POi6TQ7BVvKta7mR34QNK33beepIufPpw2W/46412ou5ZDYrJp+34p4GQJnvwgSfIZ
         uSox3Az3xlaPwfZbMoQkNty1b7fnf8FSWVNlDU2kZD58GNuv5jHI8PgHzfM6MEqJwMnA
         0FAslho6wi7FlSC8C6s9fLKiNYyHgr3GyoF+JcvHMJjU4OqdtUunyz7a3mUyIG1oGsHI
         qHCTjwzM6RIajjjYx1sAOAePjmtgh+7loYP+8/Wf31YLZHy4AxJ3GnUoyulCmwsasS0/
         LA+vwZH3YDDFCBdoUE80h1ZGIYNl39KA6QFn+W92uPSMDWm4j5ZBT/ZbfLULR/kRmV2k
         yB7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=krqnOGhl;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753193369; x=1753798169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Poy4bKsx8eR5468CsaTfzRZUNt4KSo08NHb4ysrnS2A=;
        b=C2JLGFGODLonPovScnfbi01wsVWU4vvlxRxPNxz7yOO6Tf9rm7nTbUgslvX8ZxeGKJ
         O1VN0XIH2MJSw8kmASqvEAfSUHqyU6HjwvDMpm0JF7w/oOyF/DDWv4xhqDymwzgXJL14
         65W1X6BEXBHYZKxprfOwlz6OcBVG7CDK0qyNPd8EQWHjNdvwq52BNcLBPUr4AFflbt5C
         Ku4/vxPyrneHVV9coG7paZDvV37GgYR3Zl0IM3HgBsx9hST1mf4Lw7hTGZI/RinLzgRU
         7KFruRQ7ZUGlBr6DZsNNKQtU5ipdkxhZBEWs3RG76q12ei5MjIbeU9KEJFu8UHh8ufD8
         JXlA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753193369; x=1753798169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Poy4bKsx8eR5468CsaTfzRZUNt4KSo08NHb4ysrnS2A=;
        b=mx0u4UhzInRUFAvpEY67Os6oRZ9UazpzT0TRUkfgCYzkJb/YOAr1AUPIyQ2YDRXrSZ
         nb3WiFECcIO2yiD6Mk1YJaZm0VHSs+68YDPGJmeKIf45KkEMuae4eEs7flRTE9LLxwgQ
         OU475aRO1Uu96VBak5G82QBbAYkg1W4Aet6ec7Sb2jDd8S2BIBzGkJicEgveWkJfXsxD
         I8O90pywGb9mdqlZPcRnhKtF1htu6pv464TtARwsU3qU4GbFBgQRXb+DYO9hFd1MzAqv
         CPGPCs13m7OZ5/cJXTuMin+oz6esc3EF8pD2zbrgR1S4cJtqNdh8VEwpJQB2qWWGG+Jl
         WVzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753193369; x=1753798169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Poy4bKsx8eR5468CsaTfzRZUNt4KSo08NHb4ysrnS2A=;
        b=SV7vKv0l5TuALZ8l2FOaup3OmcWLxQ0XqQTeooDyY8LyJV0ufzB5YoMnqGeL/Sg110
         FMsTM6uO1P+C6KGkQJw314a8oQsl72doo/YRUhvpjqx4KCIsR4mJd+UabY8iriW9r/7l
         iG+Fjb83PpNCSdezcEjjGX7MPlER9UmAIVCNErj+LffTFszJsoVmsM6XnccT0uJZz5Df
         P3DNbhVp6PuzQE877x7fK7U+lsNBOdhhxCSE2180bP4So1vm2+rjEITUddsvyBoJE9Ry
         ttINUjkEOxKloUDR1iJHGDZlzdAemijuxnpp5X3tAfEGBblp5DdWzhYrCveCVVNuHBPv
         9kYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4dJTyKpQTn14SnwNRBOTR+5DKuIuNy7Xq2lB79ub1nJA+EKKTRU3g15faVh/j1SmHRNccig==@lfdr.de
X-Gm-Message-State: AOJu0Ywb9cVMPX5McZQvctXL4JKBUq41v/1kxWFYBL+OU5YE+h/Ki+va
	q0ym2aB90e055wWBnyRv3P8aaUfUx46GFiCWLn7NIfPouhx0LSe28PvK
X-Google-Smtp-Source: AGHT+IH/kl9QKFzbw3G8JpQ7hX8i7vk/RDoz7EqYJPtnUm9IFM0ULQnZfVkWwvLpUfkCHdKNF3X4vg==
X-Received: by 2002:a05:651c:3047:b0:32a:8aac:e450 with SMTP id 38308e7fff4ca-3308f628ce0mr63308411fa.33.1753193368912;
        Tue, 22 Jul 2025 07:09:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhyl49EMnnzfKO2bYdmvcLkw825BXZTudZ6g0YnDLgsA==
Received: by 2002:a05:651c:31cb:b0:32b:7db5:4bf9 with SMTP id
 38308e7fff4ca-33097ec67e2ls11801841fa.2.-pod-prod-06-eu; Tue, 22 Jul 2025
 07:09:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXscDLJJF6qCBvqwCmkeQnDrE88tDY/OMm3TOFKuE7E0dH2o+l7ixgbyXd9kC7DGh9aXjmjD2TVt9I=@googlegroups.com
X-Received: by 2002:a05:651c:41cc:b0:32b:82bf:cc55 with SMTP id 38308e7fff4ca-3308f61c7d1mr52013101fa.31.1753193365767;
        Tue, 22 Jul 2025 07:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753193365; cv=none;
        d=google.com; s=arc-20240605;
        b=IUv+TF0iQnHnrvlSsT5QopgXzAYPd4LsvVjcQ7PuSDT8LyfHO2nRNcOJM/c5b76JIJ
         eBsf76Ixy/DU02frLUqVjF2Ya62boO0BACUWzYl5nsufgtSiNSMr73uyoiTvofiqLaMx
         knUYkhPONFdMg/Uvg7ouhZnOudGYt3JS+OKkB8vCESm6Jcd5mDsnzV0TU+QlqSX+YQ0k
         ib66MDbnpUKWEjJDPdIpaPa324e23HLqynkdnuKzfu8qbZBGCA4I+MfJ1XyHjexuSsSl
         zsHUNLGjdryQ8V8b3cSFiIVJ9rSTMUORG0AK/iVqaOlBmfutKxk7R2xnndaQ6ReAe+Y+
         zxMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z72Y4lywtzmWJK50j4gaS5KcylDNvYHYQchCkK6Shzo=;
        fh=XO6aNdbnOaJVAzNFquplW2Iht8Q/VhxdzIn9PVK0bvA=;
        b=WiC04wX2/e4L830jYqT/FS0bU2gTm/gYQ1w3cbJieLCvn3dLhPiJdrM1wflHaS5/Qk
         3uyeJwfBCt222jDJ/xsbqgtmXtcDL6xFYMu66JQ3RhEVriglJJPjxePvF01lWrY2mOom
         tKJB17j/WC2lFh/4DTzMjs9aFaZp6+L5rWIguq+U1X/2lpShVAryRWTX9jSesiEL7ywD
         sKX5edjjktbqYiRkch8jcs1Rl4BHYorIdgeXc1Mr3DxrYt3XtWn7ZezYJBg2IU53RyWs
         WyhmqfAEeVlnmkBg1K8G1FV3r1kcZQCRAOD4BGTOnp3YR1swR6h3qAW/P5mY5cEg5anA
         ogKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=krqnOGhl;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-330a918d7dcsi1512101fa.4.2025.07.22.07.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jul 2025 07:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id 38308e7fff4ca-32b3a3a8201so49812531fa.0
        for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 07:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVI6RXZNTCOneW+Lw73/mbzrFSPjgpeD1YWqGpw0ios/S3DBEu4rlNqqcmpmFXKUAVtKehCbHzynAo=@googlegroups.com
X-Gm-Gg: ASbGncs9Wg+z4YCFUv1v3jdWdvepJbSZQQSAEAwP/fob7RkfkXTb963NlJ0U61uFDf4
	HbknzRjM513Ymq8yj3d16YgoXmgf8yqRpD9nxrNtEBZqDnXSCK4MMbXQdVCyb7cNogmTM9XpVES
	uri7HtqZydSxnoEnNfkx/BClJzM5SLN3jR3Uqh0japsfWMcFPxWHz19xJZpNnMvOP0wC6b1AsYi
	kd2OO8=
X-Received: by 2002:a05:651c:4110:b0:32a:885b:d0f with SMTP id
 38308e7fff4ca-3308f5e2852mr36383791fa.24.1753193364861; Tue, 22 Jul 2025
 07:09:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250717142732.292822-1-snovitoll@gmail.com> <20250717142732.292822-8-snovitoll@gmail.com>
 <c8b0be89-6c89-46ed-87c3-8905b6ccbbeb@gmail.com>
In-Reply-To: <c8b0be89-6c89-46ed-87c3-8905b6ccbbeb@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 22 Jul 2025 19:09:07 +0500
X-Gm-Features: Ac12FXxpDsEYsUfFuRK9xdlLStcuqGTW4Nrf9JrgjFdTiyEs4CW8gE7SGsQYdo4
Message-ID: <CACzwLxgjKz-bc1w4SvGu-EeoMvK9Dh=2WpB-A_zC-u7H38QqVg@mail.gmail.com>
Subject: Re: [PATCH v3 07/12] kasan/loongarch: select ARCH_DEFER_KASAN and
 call kasan_init_generic
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=krqnOGhl;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Tue, Jul 22, 2025 at 4:00=E2=80=AFAM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
>
>
> On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:
>
> > diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/includ=
e/asm/kasan.h
> > index 62f139a9c87..0e50e5b5e05 100644
> > --- a/arch/loongarch/include/asm/kasan.h
> > +++ b/arch/loongarch/include/asm/kasan.h
> > @@ -66,7 +66,6 @@
> >  #define XKPRANGE_WC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKPRANGE_WC=
_KASAN_OFFSET)
> >  #define XKVRANGE_VC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKVRANGE_VC=
_KASAN_OFFSET)
> >
> > -extern bool kasan_early_stage;
> >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >
> >  #define kasan_mem_to_shadow kasan_mem_to_shadow
> > @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
> >  #define kasan_shadow_to_mem kasan_shadow_to_mem
> >  const void *kasan_shadow_to_mem(const void *shadow_addr);
> >
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -     return !kasan_early_stage;
> > -}
> > -
> >  #define addr_has_metadata addr_has_metadata
> >  static __always_inline bool addr_has_metadata(const void *addr)
> >  {
> > diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_i=
nit.c
> > index d2681272d8f..cf8315f9119 100644
> > --- a/arch/loongarch/mm/kasan_init.c
> > +++ b/arch/loongarch/mm/kasan_init.c
> > @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata _=
_aligned(PAGE_SIZE);
> >  #define __pte_none(early, pte) (early ? pte_none(pte) : \
> >  ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_sha=
dow_page)))
> >
> > -bool kasan_early_stage =3D true;
> > -
> >  void *kasan_mem_to_shadow(const void *addr)
> >  {
> > -     if (!kasan_arch_is_ready()) {
> > +     if (!kasan_enabled()) {
>
> This doesn't make sense, !kasan_enabled() is compile-time check which is =
always false here.

I should've used `!kasan_shadow_initialized()` check here which provides
the needed runtime behavior that kasan_early_stage used to provide.
Will do in v4. Thanks!

>
> >               return (void *)(kasan_early_shadow_page);
> >       } else {
> >               unsigned long maddr =3D (unsigned long)addr;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgjKz-bc1w4SvGu-EeoMvK9Dh%3D2WpB-A_zC-u7H38QqVg%40mail.gmail.com.
