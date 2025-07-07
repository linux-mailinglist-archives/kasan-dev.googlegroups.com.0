Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBZXFWDBQMGQEILSN4PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E994DAFBCCE
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 22:49:43 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-450db029f2asf16027935e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 13:49:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751921383; cv=pass;
        d=google.com; s=arc-20240605;
        b=RA8f4JS8txNxRWJFWtBDoO7HtJ1E+stGvGpkkf46C9egHm3gcpJxyGyRxoSwHLbwSA
         nD17Bbi78ox3oeGKmAvd7PtJWuxxUMceKhtbS7FVvREmSQDLOzngFv+bVeHDydMnqCKE
         hLCaGfNvbE2s8nVoOEXm53siAMpRItmSPDXbfUUghJ1ckMjIK6nxPSqD5ZOqvYOAlrYF
         fM2rekDPmE6jfU6eGIT/WsWVZfmP7zJdycO823nZ7Cs60B4F1Udm7GjIHoqZYijLkd0h
         iPnSU/2DTP+PzYtj6z11NEIPbHryTFYPOKmnn/j57TGcRGNoHkfO1MxCOaUu6tbXeAlG
         rVqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Ae6ZTvJrEhVr2HTdTI1NxbrGzfC9H/F4j0cKeVm7/i0=;
        fh=/x1aX5nOhi9nIjjK8ELAwjIBZ9h08XHNpypQ72aI1Dk=;
        b=DzuMLJLbk3eZBeAerV+9W+YVpYR+uo87cMpKLBJY2x94M/uO8kkk1vxbEBX9xQHy4o
         Aou1Mtaet6VHvpa4/WuadpT3n34W/Gxt1IwKpAR+SkolAhFja8NS7XUgYUR75CO7YAKD
         EvniXKYsYRcq6LG8xRbRCTc3iWuEjBjVzYz/wPswHZE0vPBWN+qt7Y+PUmGgohF6JUvB
         RpYCJB1Pp97MG9FS30mH+pHPCLKOoG3iht1VOojuuQYcXpopT0aaIc9U0vQhCuwPpfT9
         ka3TlFxr9RTCJN40umnWKfzG7fP3n9qnpW9j876iYTP/Iu5jxK49eJNa/cQ0h9aZqdZz
         v+cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Ab+F7ClH;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751921383; x=1752526183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ae6ZTvJrEhVr2HTdTI1NxbrGzfC9H/F4j0cKeVm7/i0=;
        b=xfWaqCazM1a3KRB6YmwJKhXa+Y+9tEkR95o8wU/aShDX0DPTJsSDhcuGcvk4/Celwp
         2Z4WMFN7AU9PYmBYG8l1p92JIPPy8bc6iQsozLHoqI4Jd25hlMsuUwiK0wpgkRWcjghy
         /7QyNhTBqIpuA0QkEsRHcEg632ZuRvgctjnkDfsRW6NgWFfV0xavUwAwLq174UbNcpyw
         JtNoa9uGehgGRlAxhKllwGTiZaLdKGIJe8j1oezn9JqufrEYT2qqAZtA951XTPVGf5cG
         cf2aLCdt5hvHnrfC+vTzpD/DLsW7pqncoRBRiJdauGHKuDwBZovWdpfAhOYfBMQ9NP2V
         /kZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751921383; x=1752526183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ae6ZTvJrEhVr2HTdTI1NxbrGzfC9H/F4j0cKeVm7/i0=;
        b=pewK6z4Lsnk/qgRtOXTooxng3pmsvcUHUReyPhbJcjjGgVk6LowQiaXI7uStoFhE/W
         4MtJrTx321VEpwoQhkJB1qfLt7ZKuWTHb9JFFeRE4Ccf4DspnViNxvwpfT6INDnybwdO
         hKHxSODSa00jmQHbl7OdIXv6QsP4nR8jAHJKAjjYfilvrPrFdWlqso6r4xVsmPrjrC4p
         Ce6OkQkAWDJsYP6Ak+rOfEwWhNhnvmdFyMX/Joo2QQZQN8MLtqjOHPDduca/b2C4Q1pJ
         1WFcq2bE0O6L1sgC31VxI4qW2rE11/aS5pViOgzxaVt3PdhoJYYwHXy2g+WNxMfTOqV3
         jKqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWNI6+FF7KO012rKSFV6eLaHSt5N8lwJ9HwtgAb5clWreB9Ge1NUPHNPXwjQ3c0H7CuobwnVw==@lfdr.de
X-Gm-Message-State: AOJu0YzHHe+Xh6yR37fPJXbeMSQp0wRD2pGD3+lpyDwUa3eBNleuGL7V
	3wThHhnlzYAIJhRlfhDXIkEjw9zoP2fbv3BszhYEIcHWaDccd3zuDX3T
X-Google-Smtp-Source: AGHT+IEZNOqs8ajN8abfgtg4DPpKsA1aXjifCAAdczX4Z3MAjIbNor5UwekAd6Vbr38yX9BwAdIZ5Q==
X-Received: by 2002:a05:600c:154d:b0:450:d00d:588b with SMTP id 5b1f17b1804b1-454ccc7ff08mr10927055e9.9.1751921383078;
        Mon, 07 Jul 2025 13:49:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfAHlA8mu2HO/5E9hVmLiNMpt+E1+wp1ssKTFYGUAIFPA==
Received: by 2002:a05:600c:3e0b:b0:453:dbe:7585 with SMTP id
 5b1f17b1804b1-454b5d08b39ls16495905e9.1.-pod-prod-04-eu; Mon, 07 Jul 2025
 13:49:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEfzlUr9Z56/066wzke0twmah3eKAT0Cmxx3cCHKUSAS+4PIUVNfLXALOtHkoRc/Ffsjukbm+KY34=@googlegroups.com
X-Received: by 2002:a05:600c:8b84:b0:43c:f513:958a with SMTP id 5b1f17b1804b1-454ccc806f2mr11457515e9.13.1751921380092;
        Mon, 07 Jul 2025 13:49:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751921380; cv=none;
        d=google.com; s=arc-20240605;
        b=WP5JZmMmtuvH+ZAVBLcfVCP6YadoS8CHsQSgpZVTc4pqxOxW65QRxYj2pBZnEp7qXg
         SDUq49vlUV428CfpHSsztpf8IHj54hmg9AoKZaov+pNG/ZvW2ysaZGfkrH0J1egM0a16
         N9hRkZMAMGi4uuW4E0+9fYIInrELKOavlc8REk8x0w4MPWLuorBHv90kb9qN6Ongmer+
         KmncrjAwxuR1RKY9Xre7AJMTXX6lN3lMbHQF++/akY9k8oHIPNwE4M0FZ+A+Hj8G9G1r
         clKNuOZY148cxk08MMH0GiwHNwwRMoTjJaGRQgTeIiBMAOIPjx8H+OUKpZHMWykSQlBN
         qx/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=02PgiN7PJFVFaSl1V+OWG4TgqqQ82M8yAYvu32Fbss8=;
        fh=sKzJvAC8MMYZ/Jxw9NEWhIV5xid8rCXEzd5Hjl3MZZA=;
        b=BklPy+iuzvmJoIwf2lcSGX2ylS5vaePUlXlU7RsWdb1ytOOC5anUfLqjuFiPHwXbDI
         ZVbM6+AMqQzK6bv2gchvoxjSGm3oa2FhGE44b80MqQC8SdlCkJh7zefoqHYkCcfJHLGp
         s9nJSmr01Qg51lHGfDHeh+1EhAtw76KTfFQ1lCKtEheEV5hspCtNNxeuikhHHMaBWgV3
         v+V7Y1pUYUdcIq8F/X8t8id0JhUSbpHpoI93SLgL3oEA1Z4vBdiUWOzUjrLtcyFqon6v
         zHtAH+WJvEr9FSzWoo+x3BfhlXL3NDMB4xO/I3O6mgUAJphlydKO0Hg1jsokjPm12lOQ
         gtRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Ab+F7ClH;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b471b93792si303229f8f.7.2025.07.07.13.49.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 13:49:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-ae3703c2a8bso721468566b.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 13:49:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWUMTNSxm1OdaUpXI1BK9o9xuitrcVVdPMYfYAmtneP2RdBziQg6N0LjRealGb9XKodWZwgH15CdfA=@googlegroups.com
X-Gm-Gg: ASbGncvlHY48QNOwV5ZTtlGlb3wtHoj2iyOOtJAtdpkQaOX6QSMdFyW+7LmeWGN8U3r
	koeGVmMl0FALWEmHa2dPuEJm4DwLPBV5vmX7mMgL8MIQXYR/L+n8LhCib+12WXeOVJlXiLAZV1e
	KDFPTCBUe/tMX/d1XEqVwQE1r7ovt03CUg2sPelYCQQjXqnLnGivf+mJrhFZ2XySbXxWImFHjn+
	RpFCbK53KAUQTzDKgWzLzaccQRC6mbWyrknc+BBdb0gGwT9oYqi84LX/q2chWF5kWzvYwYTOII2
	2bPBaNZlK7E698YWhzT9/8vVpi4wWwIehllUzGbpAX1Z6gpCT3iHrObTphd+mIoYNJrcBYvH5AP
	T5gcBwhcLmOTO2NfNVLIfZ/XmjHHmSrUNRMo5
X-Received: by 2002:a17:907:3d4b:b0:ad8:a329:b490 with SMTP id a640c23a62f3a-ae6b00c303cmr65103666b.23.1751921379304;
        Mon, 07 Jul 2025 13:49:39 -0700 (PDT)
Received: from mail-ed1-f48.google.com (mail-ed1-f48.google.com. [209.85.208.48])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae3f6b02a2esm763696066b.119.2025.07.07.13.49.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 13:49:38 -0700 (PDT)
Received: by mail-ed1-f48.google.com with SMTP id 4fb4d7f45d1cf-60c6fea6742so7543858a12.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 13:49:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSpxmVCQ1Q+bIWgBFhQtlX97+NrAnHRGyo5GxBbZaF+cPKCeYs4eykJR0Uys3ZBS638qH0A9rpywA=@googlegroups.com
X-Received: by 2002:a05:6402:35cc:b0:60c:3cca:6503 with SMTP id
 4fb4d7f45d1cf-610472e9b9dmr1045719a12.32.1751921377273; Mon, 07 Jul 2025
 13:49:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com> <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
In-Reply-To: <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Mon, 7 Jul 2025 13:49:20 -0700
X-Gmail-Original-Message-ID: <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
X-Gm-Features: Ac12FXyBZiGga4SfFrcaUHuYJV_R_nCmMtiL9Yd7402tdLFKvKKk4keGfQkJ8kk
Message-ID: <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Chao Yu <chao.yu@oppo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=Ab+F7ClH;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

On Mon, 7 Jul 2025 at 13:29, Alejandro Colomar <alx@kernel.org> wrote:
>
> I am in the C Committee, and have proposed this API for standardization.
> I have a feeling that the committee might be open to it.

Honestly, how about fixing the serious problems with the language instead?

Get rid of the broken "strict aliasing" garbage.

Get rid of the random "undefined behavior" stuff that is literally
designed to let compilers intentionally mis-compile code.

Because as things are, "I am on the C committee" isn't a
recommendation. It's a "we have decades of bad decisions to show our
credentials".

In the kernel, I have made it very very clear that we do not use
standard C, because standard C is broken.

I stand by my "let's not add random letters to existing functions that
are already too confusing".

              Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhQ_0qFvg3cugt84%2BiKXi_eebNGY4so%2BPSnyyVNGVde1A%40mail.gmail.com.
