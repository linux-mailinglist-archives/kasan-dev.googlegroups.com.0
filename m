Return-Path: <kasan-dev+bncBDAZZCVNSYPBBAU33K4AMGQEM3JWKZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B15D9A70EE
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:21:08 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6cc32a0b26bsf77419506d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 10:21:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729531267; cv=pass;
        d=google.com; s=arc-20240605;
        b=E7NBwEEeKbR3cKF0ZwN37JP1j1ro6fh8TTKVrrDn5xSsYVUludvFxGGLvrCb0VWTGI
         DuoMqMMqMiqWTD/A6gdJQuUR/X28u//969uC+mR5/gWuSThi2xRpSzEes5y30FSPJSMx
         CCmJYikMPcF/xm2IEdCI3UEMAvpSny5nvpTikrv5/Ugbcekm5/Q19hyYEKsIKjyqxyL3
         Y5TcRaCauWAFnNOLIacNQcWfvosRiAf9eKc5ASLYwraTp//B04zi/zc6+tumSvH2RZwy
         /jfazr6qbW1fuAHJEYkskr4vMLDimT8UJ7G88gHktn3DA9HQEqN8XPh1QJWQwFw6KfZ7
         0NiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=BBWXmj0R8XXNbhNGAOOlu1sRIUdFwTLIo2ggqSHbXMg=;
        fh=xwdUKRCp8SjCVA5FG/sVvKQsjyhheOxemSU+StMGwjM=;
        b=EK7YtoNi4OSeTHiyHRJKaBFMZbI99pHh0bUrHBU4Hb7ufy+b0ZV2HKaDYe2+6lWt3U
         TdaDk8+3F4EZ9UjhZX6omECdIPnre4suHYgkHw0D0Rmjch23iJrLgxoyMhtOqUtvgFX0
         ZIhTrp72ZpTJ9s59bdIu6VYHzvlpL2YXAzEGlTaChidfO0jCKfe4hmSBwyPuL6RrWyZP
         EGVYPBI/citnZpqVza7T4RkvoHEgqy2z1/OI3Ox7t/D67iHmgtkkg6M2rEHEFw0hoWe1
         b4LiMIgzhlzFk30wOaVyTn7vPXrfW2K9Oivbd+dggS09jHriuma3u1rs0+SiwTBCj+Ja
         cfSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SVanfBgo;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729531267; x=1730136067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=BBWXmj0R8XXNbhNGAOOlu1sRIUdFwTLIo2ggqSHbXMg=;
        b=Y6i9Zsqif52eEpYK2+OCZAFM0e7p7gt0sHNdygnzao2s1VYFj73U6GYMN93Nh08z/T
         fEg+IYpcTEt/is/FRD4BQsa2ezJWLkMpaqsfCQzQ0zg0x9I6GsYi1tSMFU+OK+pR6aA6
         YI+O5jieowL7Vw5+CkGPT61k1RrZiLexhTU66tYfhz+/8BzBZVPGu1gSh+YzxD8B4SuO
         us5c02tIGnzZbceqnoJwZY+D18PLh1XIN10Q3HsIvBJCBlB61ynpCumlcMkKs8sytM+x
         ge8UN0+KwDle8jAbKFJBSXNQFKyIqSJoKlELbvQulE3MdN0GDLOxUBjOdTFlFiqfhcV0
         JDLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729531267; x=1730136067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BBWXmj0R8XXNbhNGAOOlu1sRIUdFwTLIo2ggqSHbXMg=;
        b=Oo0vIu8dfZQa7CemgzcHIl/C6X47oIFz9dEQAw3KmDVK9Kc+dv3XtZsGPrZLFjAqm8
         a04Jq4F3vB4XREIQtB3CcM6hyTJSVWKmCloJjIbhCN+JDu6a2vM6L0elw8l/EJaAiDkj
         +PMyQIsvdEYGNQBrREgNUxzz5c1wG/ekbmfu17AzlqTszDBeWfoDqbRVBOO0A66WuA1U
         SN7j3HiISQBJWR/xFSwG6s66cz5L6utfwoz2MvOyU3RuMNKUdBZ93qerB+3P/1GOQ37Z
         PjgnlaRFUy3bFUd2iaqu808QytEBMtnW29IJYHmy/wnHzcF0f50tg06ZtIUnZJBY2Sax
         ETEg==
X-Forwarded-Encrypted: i=2; AJvYcCW3CklcPgAvTquhuhRDfTbrcyeiOPY6FIMnf1pizG/oFHIq7jOCWddg1mV4kXoj0d43V289ug==@lfdr.de
X-Gm-Message-State: AOJu0YzGiQb/Gvaelz2OzH8FYou1uLHCzg45KcQZbxs1AKF/m8sj9BVY
	Mt7WRcH35ZOduEbbnG/MUqfMrkEb9zmtVacj5MLz6u31DEHs5mS4
X-Google-Smtp-Source: AGHT+IHs/uKBHivGMw1MYj88qKaYPHp24McJHqaK5vyEKQapiohB8TXHOdghkQAKr923oxLr7Oy0/g==
X-Received: by 2002:a0c:ed46:0:b0:6cd:ef6f:830b with SMTP id 6a1803df08f44-6cdef6f8312mr116616166d6.21.1729531266909;
        Mon, 21 Oct 2024 10:21:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:cc5:b0:6cb:c91d:f3d2 with SMTP id
 6a1803df08f44-6cc36d913d2ls87611826d6.0.-pod-prod-09-us; Mon, 21 Oct 2024
 10:21:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVq+287bfCt4/bQRXklnvX/lkuJ4Ll/WKSGvpU0PBzF0gTMhMobsRReKwSxfr5Kphu1AEmq5le+fDI=@googlegroups.com
X-Received: by 2002:a05:6214:4341:b0:6cb:ef7e:9bc4 with SMTP id 6a1803df08f44-6cde15da00fmr198330296d6.34.1729531266357;
        Mon, 21 Oct 2024 10:21:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729531266; cv=none;
        d=google.com; s=arc-20240605;
        b=ewMqL76mkbVcFkBSCLz7z4Nc0m3Bltz6sK79w3figi5X0BHnvF94vipo1QBBUu8qRP
         T98qO/PrksfuM/o8O5KWIDTzeRztpkbyvtO5qXXtwZUad7U01vdacyacZNe5y3Kvwv6H
         FyO8/UH6TFqAbaCesmGkka1RvOg4A/d8mbEFkrMZygSZoT2ttl2lzSENxrNwfS8Ul4DD
         kBAZSHklgHkXkistelFhyKUjNOA8AFvyz8Xy7njul/bZQbPL5DjLJFuKLwONNfp8b6hk
         /94G+D2garnHP8NCw06zw9o69rjSRdQEL7ReKiQ1g3lHUT2JSWgKe74Vq8H4iTprGBTy
         qwAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DTP1XGaaQbsAcwwphKjb5a6yilGG1yNK2JpTeix88TQ=;
        fh=GRkDb1ye3JSfYOQBMLut7hlXkcqh89mtEvceyp2bLLw=;
        b=BJapwJZkz6bM2oHrqPF0gf9quuAJNDmdPQ3Bvc+VuSgsrHIJlz8i2kbtddGHxuPOOX
         +HkLO5oYyqGdpo6vB+Utf+UYWqIlP+gu5UUzWecQ1zJel5Kmj8wq1ptcQysoSMYfLtbX
         afBeba46UfFz+c7Tjsd/vBiic1biwzLJT9+xw7pKjJ+fuv/Y050cAjG4KdQzqM3Jv2eh
         Vb1s7PwdNEghIy2auyxW/NEyeLzNDNyFnrTdtuVg3avnHO0qtk6Y6fNy2eq3F7Wbl2+5
         QA01tAWG1gxcFtCIQdxOFgx+/48HgUSw09YTUT03b0XKZjX4YikLRCLr3CMBcuCSQ2c1
         ixYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SVanfBgo;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ce008f5a76si1584046d6.2.2024.10.21.10.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 10:21:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4451A5C568F;
	Mon, 21 Oct 2024 17:21:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D808BC4CEC3;
	Mon, 21 Oct 2024 17:21:02 +0000 (UTC)
Date: Mon, 21 Oct 2024 18:20:59 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, llvm@lists.linux.dev,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com,
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
Message-ID: <20241021172058.GB26179@willie-the-truck>
References: <20241021120013.3209481-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241021120013.3209481-1-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SVanfBgo;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Mon, Oct 21, 2024 at 02:00:10PM +0200, Marco Elver wrote:
> Per [1], -fsanitize=kernel-hwaddress with GCC currently does not disable
> instrumentation in functions with __attribute__((no_sanitize_address)).
> 
> However, __attribute__((no_sanitize("hwaddress"))) does correctly
> disable instrumentation. Use it instead.
> 
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117196 [1]
> Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrew Pinski <pinskia@gmail.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/compiler-gcc.h | 4 ++++
>  1 file changed, 4 insertions(+)
> 
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index f805adaa316e..cd6f9aae311f 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -80,7 +80,11 @@
>  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
>  #endif
>  
> +#ifdef __SANITIZE_HWADDRESS__
> +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddress")))
> +#else
>  #define __no_sanitize_address __attribute__((__no_sanitize_address__))
> +#endif

Does this work correctly for all versions of GCC that support
-fsanitize=kernel-hwaddress?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241021172058.GB26179%40willie-the-truck.
