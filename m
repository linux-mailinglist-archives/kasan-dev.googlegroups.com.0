Return-Path: <kasan-dev+bncBC7OD3FKWUERBFXYVKXAMGQEA7HI4ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C20E852440
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:47:20 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-5d8dd488e09sf4864980a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:47:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707785239; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkpKDrcWibaXyf0yzNsHEAdsX0fYQq0D3ZS4zEF1CrvsRJXuau8qzFaIX3rPNKjjoa
         tV6a1w+2/FABDb733bitRvKqf3HF7/uNTiDzs7BZetlpMrhmmSJsjbLQlR4cMWvlfUV4
         V37+60dVj6dudXl+Nj1cnKUGCcsNEvwoNKaHdJ2wdQhz3gR7X4lBxrSwDLmblogJc1Qw
         9AoKiWJrO2b8idPjE1tT+OfeypivUP5ckfxWxOAJvPptHajK7/sct05jiVI9AmE8NPZN
         fT3fsV5zx33qA+4H8OchtGgKyQGtT1WUIPWFx2Rtrs7IqdDiwDymzhL0p6GG9QJCA4u0
         dVSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=p3Bpy0r3DWdny8FHTEmFw52kdmQCHS2xTCe1ZX03wdg=;
        fh=EHFIQ36mjsOQVl/5tzI292D4JsrFLjsmuHeQOEtzevA=;
        b=J3EgBfyG6seIvwZ9r49elK2R9gnW236Cmmbtnzl5pzkev1Exu7q6ztixeUaLMmaXwO
         EV1QVi+uVBd5zdbQs0YdqcfDtVmNpK9o3MYN2LPfwqSHmhI6ox7Ad/vme8ams1n9Mdn0
         2OvTYDrfc+N8fYI4t22E/xFJlHC/8r28AwxLMkCUCLiNRTiH6XLaSZp8dKwenFULAasr
         C5IfYtQDp6ZTe2OzG93AoiJ28dk+AhQ+ExmPAORHP2HI9spyifmvx1pQywoo2L7OplGt
         4syiWJhvnqpF8QnSvC6Zf94W+BtFJqPkBgMUiDKaHCjOBqPHg+f31hf2mPI0akcbN0IL
         F2hA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wn+89KZr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707785239; x=1708390039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=p3Bpy0r3DWdny8FHTEmFw52kdmQCHS2xTCe1ZX03wdg=;
        b=rDcSBXdV31X056KKQxs4U2Q0QroOzFuRADBKhtygHJUoDZJSlpN6UONUDkK/szFmOS
         AzrOfjB6XrLs7Nu9d9vpJkOQmXFRSnAo2yDmK/4t0I+zN1+5w2ngIVfD4YM6Oz7mf1hC
         7gGUVQb+wHZDnjEzQSMlXn95tenbLCSlgVKoeGb9oqL4wYQf4oFtvdNCMDNlStaANOv+
         sPntf2uUTAumqhNql43kXbloTyTI/8EwjtU/gNmz4FgEj2EuL++FCPnJmtN9TROCtgOO
         0hgcA4zOUehT1+KAIYWlt3s5Qu+OpwFZGPWsp99ihH4XbRLAnbmarqRziP2nVgvwR54U
         okzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707785239; x=1708390039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=p3Bpy0r3DWdny8FHTEmFw52kdmQCHS2xTCe1ZX03wdg=;
        b=XBrkTaXiN/SD9Wm1ns//31PhA3f5aQtAJV6JVFv1CsErSOIxQep9S2qHXK7wp3wjBB
         5ch/UXrInJuK/Cfmb7fXZenRLw4HwxWFHZuKc2Zr3n0DyYWHwBue+ukFohkUoO3LF+sN
         NhkJUss9/kO/rVGjTBR8FziGMxtpjcjIElusOuUGq8Z1Vjr4p+y5MQiOxTgTiFvzB3Tj
         9YP8SQnXNSTrgVsG5y8ofh13876Z6G6/hsKdz6aX3EvaQxFE9RdqgBudkyboceNIkB4L
         DikxBymj76y5tJHM+x40AR7ssadzzBM4MWhy+Cn5NhuROYxXeTncWb75tq/xFIv2+Wxi
         SwsA==
X-Forwarded-Encrypted: i=2; AJvYcCXVOu3NysqO+VsOiI21EJ/8ojzdfNSKUZ/WddKo7g+8tUjjDCfTBc09WLSk6DShX+Bif6rf9tYCag9a0zkRXQvcCTWKRDuLbg==
X-Gm-Message-State: AOJu0YzuGHrTWkZUgM6oOYN5EjSBMNsesdeicLWTbWFY9i8WBQBHhn54
	GYM2/En1NYLhUfqOLg+ii4VcNaF7JGnf4ies2glvLVHwTM0oSdbH
X-Google-Smtp-Source: AGHT+IEhQ3qtmC+lHH8XsC+HF2qCoEfR3G+7gVoEWM8JFtFfzhZZZj1Pfgs1Gz/uB5lt+sO8bpVLGA==
X-Received: by 2002:a05:6a21:1706:b0:19e:39d4:284c with SMTP id nv6-20020a056a21170600b0019e39d4284cmr10674309pzb.29.1707785238847;
        Mon, 12 Feb 2024 16:47:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9088:b0:6df:fd9f:7fe0 with SMTP id
 jo8-20020a056a00908800b006dffd9f7fe0ls687378pfb.2.-pod-prod-06-us; Mon, 12
 Feb 2024 16:47:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVtnlHXxtRZ/IoQXrvfXatIcYDvRdDUvuNZyFhGvcIDWyjonRZvWXoOPW6pG6Mxec22COYkJy4mCIFVS6My2R43c9Gc0F5OrrFa9A==
X-Received: by 2002:a05:6a20:ce47:b0:19e:9cc8:bf27 with SMTP id id7-20020a056a20ce4700b0019e9cc8bf27mr10091906pzb.18.1707785237710;
        Mon, 12 Feb 2024 16:47:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707785237; cv=none;
        d=google.com; s=arc-20160816;
        b=I791IkLF4sCURwuFQRJ3yj+4+HhIapFI+evgeXQSfTHP6H1f06ATyhBJMpqDEzMoOc
         s/KB771rzzZnedEf1R8CgdJPthYiyfktu8g6g7U34vlFSPrTtcacFQ1rC3bMU0mvkE9u
         tV49nOHOmvMTWw3jupj1y/z0ly1QBblCIle14kKshZmzn3s+9rjoyciKa1xZzvFg2aV/
         HgnMxNque9UOlKptfFXTQjWEeqdqY7YodN6Gg4GRbLziy1bIdSckuZ8YuY/Go6iJ74Ol
         WQOo7zx9zwihvvPeebxTOJB8iZF6mMzkwzWBfCJ35KEZ1TOksxW5ur2nMUCZv6i0qnzS
         hqtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6sfE4CKDsYgzSNtG/2Z/eISWKsnaJqJipJlJ0mll8gM=;
        fh=EYiAszQ9XjUzeWs1aVcocKjOajUkYrDG8MwDxhXZVUo=;
        b=w8JlTCQvmcwoYCKXqN0t9dQ9iAZNgiLaF5WrMv+Kji/QZACvQdWNDm9b9L4TBnhn7R
         dAAjRNxWdfMF0h3ywt+lprB4csGvrxUOo8ugGkhV9XUeWiyazQdSD5l7cO7reYSkVQSw
         d+AoNZvh4n+aTrK37OBr88lgRSD3TCssipcGD65S6eBXP4BBHnBmBKDyvQAab5uaIqPi
         OKI6Gx+oSEeWhV82ZrboCd+nRlBzvCumpGqi5yp3bHL3/Rbzz+63jus9IcEF/Qkk7nc7
         ieqkJ1RiWxxdaVkbmj9fmacJROwbZMN0Ip9XcqHy6DYh9aedbMPR0q/7oDB9KxGJNI6a
         ck6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wn+89KZr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCW36cSbZbBQBiPUepdjw9D4G7PMKz8AtLrwQW1K7C5ZrggkiS/9pQ57Y6s46m0r1q+9YIbDStqPuqGL8izXgCA/Gto8a2jZLp+Rfg==
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id w4-20020a17090a8a0400b00297002c50c5si153404pjn.1.2024.02.12.16.47.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:47:17 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-dc6d8bd612dso3751437276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:47:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPkCdNXQbU7urUP/uIe+XEj5NSKMNQdMq9cDuW8BsdCu8+nX4z3BRtfkWbAux2qI+OurTJwmNkVPCQntGo/T+DjLole+Rf+1G4Iw==
X-Received: by 2002:a25:848d:0:b0:dc2:50ca:7d03 with SMTP id
 v13-20020a25848d000000b00dc250ca7d03mr6944337ybk.1.1707785236496; Mon, 12 Feb
 2024 16:47:16 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <202402121602.CC62228@keescook>
In-Reply-To: <202402121602.CC62228@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 16:47:05 -0800
Message-ID: <CAJuCfpF677Fu152GQAgD-GW=eFPsRMXfXzyXtnc5p6kPsxeQJA@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Wn+89KZr;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Feb 12, 2024 at 4:29=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:38:46PM -0800, Suren Baghdasaryan wrote:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for=
 debug
> > kernels, overhead low enough to be deployed in production.
>
> What's the plan for things like devm_kmalloc() and similar relatively
> simple wrappers? I was thinking it would be possible to reimplement at
> least devm_kmalloc() with size and flags changing helper a while back:
>
> https://lore.kernel.org/all/202309111428.6F36672F57@keescook/
>
> I suspect it could be possible to adapt the alloc_hooks wrapper in this
> series similarly:
>
> #define alloc_hooks_prep(_do_alloc, _do_prepare, _do_finish,            \
>                           ctx, size, flags)                             \
> ({                                                                      \
>         typeof(_do_alloc) _res;                                         \
>         DEFINE_ALLOC_TAG(_alloc_tag, _old);                             \
>         ssize_t _size =3D (size);                                        =
 \
>         size_t _usable =3D _size;                                        =
 \
>         gfp_t _flags =3D (flags);                                        =
 \
>                                                                         \
>         _res =3D _do_prepare(ctx, &_size, &_flags);                      =
 \
>         if (!IS_ERR_OR_NULL(_res)                                       \
>                 _res =3D _do_alloc(_size, _flags);                       =
 \
>         if (!IS_ERR_OR_NULL(_res)                                       \
>                 _res =3D _do_finish(ctx, _usable, _size, _flags, _res);  =
 \
>         _res;                                                           \
> })
>
> #define devm_kmalloc(dev, size, flags)                                  \
>         alloc_hooks_prep(kmalloc, devm_alloc_prep, devm_alloc_finish,   \
>                          dev, size, flags)
>
> And devm_alloc_prep() and devm_alloc_finish() adapted from the URL
> above.
>
> And _do_finish instances could be marked with __realloc_size(2)

devm_kmalloc() is definitely a great candidate to account separately.
Looks like it's currently using
alloc_dr()->kmalloc_node_track_caller(), so this series will account
the internal kmalloc_node_track_caller() allocation. We can easily
apply alloc_hook to devm_kmalloc() and friends and replace the
kmalloc_node_track_caller() call inside alloc_dr() with
kmalloc_node_track_caller_noprof(). That will move accounting directly
to devm_kmalloc().

>
> -Kees
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpF677Fu152GQAgD-GW%3DeFPsRMXfXzyXtnc5p6kPsxeQJA%40mail.gmai=
l.com.
