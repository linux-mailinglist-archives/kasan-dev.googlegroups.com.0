Return-Path: <kasan-dev+bncBDW2JDUY5AORBWPCXS3QMGQE2KXWBZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 12A2697DEE0
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 22:49:31 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5c24cd1e1bdsf2713343a12.2
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 13:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726951770; cv=pass;
        d=google.com; s=arc-20240605;
        b=JB3Xf/EYTWv4o3BLJFnvwDfGGe33FjdPkeJMG27FX/wyLBYMOchOqlNlOTo3QTx4PM
         9Frm3iY7A/4ri2AdPH57n6hmpc3mt7D/sdXBhw0CeYUeqx0YheBmpgp9fiNjv8EJ/VGG
         XZlWn40rcP1At9zCiKXkzUrB/2EBcEankMZacz9OWWBdDBlSOZWJ4e4/lilxcIgkdz4g
         SF2z5bRBZUhFJ5v5HZYjAyZOdoOeTrpTEx++r3TRaa6u2dF2ryPlacc8yPz2S2RngpOn
         ZzYW6SmPv3UglH/ZYy1jz82Bi9Q/6ko1trRH4/URD0Q0Eti39priEndM4gKYMh+KU212
         es2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3C5hQvObGdyhxZzgtFoi3ThGC2F7qqrG+0UJQGCnL0M=;
        fh=JSQSzme5zl9oS4SHTRrJNt5pYpMuq1DhBPoVSsm3zoI=;
        b=L/5Gq4U3L3/iwaA74D682SaQ3mvedPr3t4iZ0sBrhcW+seJgTtiAJZ8MgTCClWmNEh
         ireA4I9NxIlX8p2Bo3LYmknt+hOc6L1/FjJ0sXwnGcSnpP06F/pqN9cuFouWek2SWkYd
         3xZUOyZroZioIlZYyBdVaXQ8fSq26+QpAW2Z6GGXRTFJ2dq+6tD6yGS+IWGCejoaoxx8
         Mldp75b1lzjgczyWiXqQetQ321fOa3UpoLCxRIVbNVIwZlvNB5AjqD4G2a7QXqq/QGGA
         BdnGkUErl2tHxxDVj55ojQN26+IwZM+bbdrerB+I/srTpUUyj8yv88Sg+TTfXx0s1xho
         r86w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=etjwZ9+d;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726951770; x=1727556570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3C5hQvObGdyhxZzgtFoi3ThGC2F7qqrG+0UJQGCnL0M=;
        b=XDB8eU3PDmBO0CPMSJVccXcxDjH7uIBCHc9uUSEU1vOcCcgTB8oIkm1mu2oXrA4/AD
         ZeD18Zfvzm/Hz/jp52qtgQMRfk7u3aDsdrFiEM5Yi4MT/qcYZxa9PA1olwuawgq10gMj
         BHkZwWYbFzI12Spmv69xmDhnGEWRBEVJl3CzumGoukjAm5W0IEZ4s1r7k67oZACU2225
         UFt4iEmfYt0jVMosoVVj0yZmx/IqEiPoZM4xzNjWpx/bZwFvjgPZmkdvtEa9/Adrd/83
         h93KsIRU8EcP7Bq83AyMHk+gDqp2hdHyacxXMx2DT/Q03fsixD8/ef6ZDMndnN8QiVHL
         9Vmw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726951770; x=1727556570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3C5hQvObGdyhxZzgtFoi3ThGC2F7qqrG+0UJQGCnL0M=;
        b=afZDDl75dKwIfunOl04h+cirPfnV6arsJoVO+O1i/BG6dI2rwPhU8JlEC5RhzxfC5K
         ybhIk73sP8mkGqvx+iuLerXd9Ydc1zjxxxVVN6ZS1MAV748P19SoZ2CoMffSNNFaV0nW
         xhUmnd5G4Kj4lVsghculvaGujb5KXR0TPrQVWLVWiGUYd/GPqHRjfCs3Usx+cfcEvOPK
         BYn4Y34verDXxasXPwtY5h33zaxGCkKxYv+N7zSXf+1oFIaXjOhcs8o3iKUTbbLXgiXe
         mw3C+sW5rQzbBcktAwmaJFXdx50z8CxpRPLnm/TiXiMZfiMclXniA2zeJn6zieZCW97j
         OH8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726951770; x=1727556570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3C5hQvObGdyhxZzgtFoi3ThGC2F7qqrG+0UJQGCnL0M=;
        b=Nwd2PmVYzgmhTWU7Wic4ZMWrJFDsE+vgedopg7bj6r9EcmP4C/s6vbU4WchyA577al
         gx4q2b5cu4fdKAdqhk8x6jQ95TIxux+/Q+N3+2cFuQWYmwnp0Qxs+4aMnQF8NTfPJ1BA
         dC1F7LNzC4+Z7pKt6gtgJRyuWHa6Rp1jrKc0/5O9ndd8QZgoAS38pIFKe6OJb7W+bKwb
         iA2mZ88gpZoTNB904QdOfdGSh369Oo3VDKabSeXRbtJ1odSQeU8qn2mTUxgqYD2urlp1
         HjJmVcnScXGOPmr2F2jAY7IN8hd2Zt9t5EmrsTpc/yF4zYcQQ/RpRVM7T8lIj146yp+1
         WPww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsP1DR7TX8yvGAYTS5oDXsSYUUBmby9mSTZ3qxoBZfWbQB8WoNVp+iuy7FoWbHuVON8Uhe4w==@lfdr.de
X-Gm-Message-State: AOJu0YyRdnusQ3JvUZKTh/4srwut7HNOdxUxztexLlg5huAmGKwH9hdp
	W02vhI+5Z6EpPCRp4CmvGehAqoNpu8+kEAmOgzqW7867weluGvWt
X-Google-Smtp-Source: AGHT+IEKN8ANQwgRwyuxTPbaqKZv1i34zeR6tOdbH3Ep16xMxwjJLSe2p7G0/CL0q88MMcrOMGyrWA==
X-Received: by 2002:a05:6402:13c9:b0:5c0:ba23:a544 with SMTP id 4fb4d7f45d1cf-5c464a3a1a9mr5501327a12.12.1726951769766;
        Sat, 21 Sep 2024 13:49:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:a6d0:0:b0:5c4:63a1:7014 with SMTP id 4fb4d7f45d1cf-5c463a173c0ls215703a12.0.-pod-prod-03-eu;
 Sat, 21 Sep 2024 13:49:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8CrU3KT9M+YKhxPZIGz5tzOr0qWsZced3fClp0UO7v/c5Dh7eEEbbPpuz7ibF31phzhAIlKOp674=@googlegroups.com
X-Received: by 2002:a50:c88d:0:b0:5c2:4dcc:b90a with SMTP id 4fb4d7f45d1cf-5c464a601bemr5338171a12.34.1726951767714;
        Sat, 21 Sep 2024 13:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726951767; cv=none;
        d=google.com; s=arc-20240605;
        b=V5f1BuDpxCuwNeCjIIkfkwTRdNH+sEaFmf/LjpzRiUnF6UNH5EtgQ9d1EUzg+ysnnB
         /560KzMUktiy5KjW61dCRW8gvAb9DDZlvmzIh14R4xGEVufykbRKAi0fUL08GfnqhyuW
         yh7ldiVAxb+GeRvP1hUoA+nzTBKXtRXJwu9k8kZgIyZgV5W02H7T3/3WRihDCz5UkdBF
         /AhiGAOWRnF1amwaSc/eXyFOISaThkus+9fy6GhDblf+GYqP1bEERt19dmar7Mqo+mPR
         O0YsKWsceCD5xrzLQsMGg6FCCnVbz98rYEZZqASg8HnY7uP4aBNLh8D7tAT0EKt+jme5
         UJ1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DpMS7wUdHk5IVkgVUMOVgwFSAzOkqlQUSFAK20B9Mtg=;
        fh=V6QQPgaIXOGxwbEldEhGKEsFbVjuB9prafeor7/GaPg=;
        b=Cq2dJ6K1wqGkQ0JgC1sH/roTIaFtmyrmQbb1TKZolX55t0TFakVu35q76ezkK6RqEZ
         EKODihOVNWxHkthHEAAFsRYlggri5K2Y03Dpu7ZGdf670fAvBNUQRyY0y9cicdhEtbeE
         J1NsX+Ss5HdVAJZeE4yb8lT/IJziu2oot36ecPXvo7SuwbEswHmSOx2XKwLHC5jRf0ci
         W0AT3AaNoJGseRzQbPSgFtjL41aP3qxPuK3GdiwEys+Bkp5Kqe3yGgVLfyT7b/TqS8zP
         ggQfmlD+hWcOM4seFc8Ie3zVlAAhXhA4MdzcRPocli468KxFntzSyvIUMOpPMHgEQn+M
         2mYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=etjwZ9+d;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c42bb8f1d4si687552a12.3.2024.09.21.13.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Sep 2024 13:49:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-42cb9a0c300so26088135e9.0
        for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 13:49:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhiF7SZB5bU1crIs92fJIKkr8MLyaNEEOXljCx7/Uc3IWlyRBtjBpv2uMk+BayOJc3+yMtSl3g8TQ=@googlegroups.com
X-Received: by 2002:a5d:4d8f:0:b0:374:b3a3:3f83 with SMTP id
 ffacd0b85a97d-37a423989e7mr3719363f8f.53.1726951766939; Sat, 21 Sep 2024
 13:49:26 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZeiVRiO76h+RR+uKkWNNGGNsVt_yRGGod+fmC8O519T+g@mail.gmail.com>
 <20240921071005.909660-1-snovitoll@gmail.com>
In-Reply-To: <20240921071005.909660-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 21 Sep 2024 22:49:15 +0200
Message-ID: <CA+fCnZfQT3j=GpomTZU3pa-OiQXMOGX1tOpGdmdpMWy4a7XVEw@mail.gmail.com>
Subject: Re: [PATCH v4] mm: x86: instrument __get/__put_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, bp@alien8.de, brauner@kernel.org, 
	dave.hansen@linux.intel.com, dhowells@redhat.com, dvyukov@google.com, 
	glider@google.com, hpa@zytor.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, mingo@redhat.com, 
	ryabinin.a.a@gmail.com, tglx@linutronix.de, vincenzo.frascino@arm.com, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=etjwZ9+d;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
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

On Sat, Sep 21, 2024 at 9:09=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault(), copy_to_kernel_nofault(),
> strncpy_from_kernel_nofault() where __put_kernel_nofault,
> __get_kernel_nofault macros are used.
>
> __get_kernel_nofault needs instrument_memcpy_before() which handles
> KASAN, KCSAN checks for src, dst address, whereas for __put_kernel_nofaul=
t
> macro, instrument_write() check should be enough as it's validated via
> kmsan_copy_to_user() in instrument_put_user().
>
> __get_user_size was appended with instrument_get_user() for KMSAN check i=
n
> commit 888f84a6da4d("x86: asm: instrument usercopy in get_user() and
> put_user()") but only for CONFIG_CC_HAS_ASM_GOTO_OUTPUT.
>
> copy_from_to_kernel_nofault_oob() kunit test triggers 4 KASAN OOB
> bug reports as expected, one for each copy_from/to_kernel_nofault call.
>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

I tried running the tests with this patch applied, but unfortunately
the added test fails on arm64, most likely due to missing annotations
in arm64 asm code.

We need to either mark the added test as x86-only via
KASAN_TEST_NEEDS_CONFIG_ON or add annotations for arm64.

With annotations for arm64, the test might still fail for other
architectures, but I think that's fine: hopefully relevant people will
add annotations in time. But I consider both x86 and arm64 important,
so we should keep the tests working there.

If you decide to add annotations for arm64, please also test both
KASAN_SW_TAGS and KASAN_HW_TAGS modes.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfQT3j%3DGpomTZU3pa-OiQXMOGX1tOpGdmdpMWy4a7XVEw%40mail.gm=
ail.com.
