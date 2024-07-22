Return-Path: <kasan-dev+bncBDW2JDUY5AORBWEG7O2AMGQEBT7MOAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 289FF9394CE
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 22:38:50 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ef23a67c5bsf20357271fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jul 2024 13:38:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721680729; cv=pass;
        d=google.com; s=arc-20160816;
        b=FQr9iCFWkyWFwuUxws7hGo6nIXew8qy8NqroaVj/8SHSwEFx1aYkomDuAyr5E7m99F
         PbjON0xBsTjlVMsElzQaDjmyUgxtS5xHVj8jwgNeZ/oZU/2xn+WD8FCfC47ewyMEG/Sj
         akfD1T6BGZqZnwUZAGyK6BtBJBSJhWD2mX1TYQjXmu3+qHjCVp5kOeLCEm200shVtHZ6
         q0SZ+kD9DUjVY+wMvwgVNd183dMOZPvAiUBsIvG65bzybImnq+cKPHJZQR+zmAJP7h6L
         gLIp0dpo0GS93Lqk8rNmx0RpmIqhI/Ekb+ZugkjM63FTa2whzm6qMt4xS3Gy5X0Ts0uE
         gbJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=24mStw95fpmVYzl04a1ohHc7kI8AFafRmGS5c+BucJU=;
        fh=oUQz0z4VwwIr8d7jVsnR/ZvaZn+5Qnppp4BcDXeT57Q=;
        b=aOa08GDO6EZlkLtbQcAeKwqAN8UAHBEndrrX60jlSCjTWHVgwiXKwwfagNxj4Kp3AB
         7OssVf1iyYiGRXryl4bTRD1LQ0ekASYjGqkN2pjRaqnl2DRR7mnUPW0f4B0VdEuXGmJU
         LyjWtZDyQb5hyLkiOBu8NO/NoBtDSj2Cd5iPGYs0mQ8/fZPfszsSNsq9Hw5yqWb7vjD2
         yrAXavTE9uXA2PxUmVnF6JGwKI/PlMHfv/+NDMli4//wMFpgw3LSWYx6lHyPMMu2/2PW
         S7tsVOVG1IkrmQozFYlat5AeoTQFKr0/fy4NOQKcCIvC1w7jsXMiuFOKf/F8WDcI1bVV
         OltQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MoiQKAiz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721680729; x=1722285529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=24mStw95fpmVYzl04a1ohHc7kI8AFafRmGS5c+BucJU=;
        b=QOWRqcfQ+Zj2zsQCGxiPOS+Hv5LNafI8sHTVxYyckwuv1PFN6TY0whHw2z9qB9QPNF
         CTAzq75WrKp461ERhM+If+3FltEpnc6l24w0oNOLi6U/JIzZWGssIHShpc4eVBSe5Ms6
         px1pZhuZ9rnDrZYaPkbHnffdwzvps2ZLy0NVxjEKcfOa3OwPEdUAdiHYN0nEh794aM4b
         fIK79uVf6ktkyVHBUN4HkBD9OZWRqdiPm1MZJUHbwEnik6/EQPuxKzhYHbBuC7BB0QXH
         IdGqW4vnARNz+Y0PVsQgH9NWCv4R7AKdsL2zD5g4oBMpwD2vhfMjuSHcMXIHuxMQszWw
         nHBQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721680729; x=1722285529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=24mStw95fpmVYzl04a1ohHc7kI8AFafRmGS5c+BucJU=;
        b=kCcQ7mbyx4c4xLBdeox3cV+9/pY9PqvfGcHGlBmFZ6QswA0e2tszlJYhXIKEDmcvCP
         kLooep7lZc54B6xRCf2mZ4qS5aQHiP1113y6+asvCGrfzOUe5k/c2ezU2lZ0Ykyg67EH
         ucZbzDHd537pYNhkyUhzFLTtyH6WQVB+6BXSrNqL9SZN8QNI3iWkmqGDl272Yh3dg+8m
         0+re4VgIjrpOQUo5v+xA+lSxIb5oi1YHbmYEkmg24MHdFJBvMVT6S+TFO8kH4ZEOum3P
         gLeNIkIrJRHh4RoJT4oRaTyyun9KTxXfJ+NLDGwVwB87FfwVylSW94c9JBjm5/7iGQyb
         +y3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721680729; x=1722285529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=24mStw95fpmVYzl04a1ohHc7kI8AFafRmGS5c+BucJU=;
        b=ZIpswUdBdfbHxF3Q8zsE9wNWZ/XjPL9Z5mrh305S+amIplo+BRdf+J/84P51pMIqPA
         cj+8W8Tm/6dHCu+D806yQ5olQtVn4wpxtdm89+J1ojeZyhEEUZwTbnnFIVNhBmolHSaj
         ZAkil3xfAzrPEN3j6uwQiZP+zmVku/OOztKU+Y/JbwRI52SN/NgJdXAuSiPG2oFwndWW
         BVXj2RzobooJ6/ji4IeBpdisGhiC92ryha4vjCOVQuAYylVPBC6hz1JHzJ2eAO3tZPGH
         xtPnHTenQgqQURcxRcwN6kRpXllLmJa/ylrWy3Cs24kYXacQv1D7gH1XnBj+JI7WxJjC
         UQTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdbQibVXtmiPNvQnAMT3W1vfc+bu8S5ZJcQf9l+LC9HmAA6zWHie8H2hM86ZQkyANoiRquu1zWKFW0yzfc0uXzyoVYCUNUxQ==
X-Gm-Message-State: AOJu0YySqblNuJ//Z2MJM0QQqEMe80nzCJJUUoB3VQ7VnaP8ekhHLgsB
	jYMMdYa03ThaJZq3K0B+cF+4JLaY6ZqipVGn1CzRVwT+j8gOL3ak
X-Google-Smtp-Source: AGHT+IHfeRtc46eSodeHe28tpwkkpduds4KN0cG7elxY743LX6u5G/m7xDDNU7uKoHDLrxYDu6rdmg==
X-Received: by 2002:a2e:9e53:0:b0:2ef:1bd5:bac3 with SMTP id 38308e7fff4ca-2ef1bd5bc64mr49365581fa.41.1721680728732;
        Mon, 22 Jul 2024 13:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bea3:0:b0:2f0:1cb8:9ecd with SMTP id 38308e7fff4ca-2f01cb8a1f7ls2659731fa.0.-pod-prod-04-eu;
 Mon, 22 Jul 2024 13:38:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwEOHaJgIFJQhrKQ5fKMTOatpvWZrmecatzK+1cX8K5c+K/EP37sIzHRm9JQRHqZzyK1zd140AMfr0Q9zmbSqdzjiXGRKMag7iXA==
X-Received: by 2002:a2e:9f08:0:b0:2ef:185d:e3e2 with SMTP id 38308e7fff4ca-2ef185de5e1mr51565531fa.36.1721680726825;
        Mon, 22 Jul 2024 13:38:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721680726; cv=none;
        d=google.com; s=arc-20160816;
        b=ONyWuj/GhfwUWi4twvyLudYZZxi6s5AcpKkRgrYMAzoRchPRqU/o/TEAt57CYzD7up
         u9gbIinaR+KmKI9zUG02CrWYW0SVLrTLG1UwiR+6TjuCApPw36Xz3LoTnzVwJywMLlds
         8wMnqxjso9H3xC2ZWSzta7jC0yE1qjQimVJv8vaeyoymFm+pBpQP4T5rKQE1beoQ8+Zx
         4yF2pYs99z59D+EasC5QzdJj2vgucES8DbMg+A0hvzu+Pn5CKtOpwqenx5eb7oYYVyUP
         BFmBmw0an6XiBdMCF8nvnbG2dOkmxhzyN9l7XQcfW7JE/eRE6zmbsBq7OphyapjfD9Ly
         Qh4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WWvxWL/SNIp/p1/ug+eVMpMZjJit2TPmzxyd8I18mCI=;
        fh=yZ0TRzWi9iL6xc+lstrqNC3FYrQbe0z3YzLsls2sUVU=;
        b=R68esnYuqMuc2sjwE+IQ7a0manNB7myrTZmRll8ZiQkhq4QM4Qvx6HUx7OgBsJwr7s
         ffxbj2XHc0A+oAdoCVJMuje6pQPbU6vk6widMeFXLk1aV2Lcv9hCg84t6uoIVGpqXBUC
         ezbfqmFqGm9Yml/6KjWffWmP4otdqNKEUZBQ7XzBBizoUCNi0ktEnYlqCvt7tf0P/uU6
         I+fHXG30f5R/v1Z0ftglDDoNaIDALZupQKoc1xOqkkht+ou9WEcGIj+9o2IPBX+vQ8go
         ZslTFEyUDhAnvskLHOZ+YU7ZdHRakENBc+atjusYV9x14zeF26VXSqehIV99qXjyVnAF
         o6lQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MoiQKAiz;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ef0fcf84bcsi1704821fa.3.2024.07.22.13.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jul 2024 13:38:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-36858357bb7so2396573f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 22 Jul 2024 13:38:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5L3COTU9vTGKL0x7z6v92BSlpNZtqoKK9HwXhS21dqxP5W8HxVqV3R04mwVn5SvAqCGxXBZPBXWjVnJIFmQU7zsgY5iZ06H9Zmw==
X-Received: by 2002:a5d:4a06:0:b0:368:5e34:4b4b with SMTP id
 ffacd0b85a97d-369bbbb3025mr4808628f8f.6.1721680726073; Mon, 22 Jul 2024
 13:38:46 -0700 (PDT)
MIME-Version: 1.0
References: <20240722202502.70301-1-andrey.konovalov@linux.dev> <CACT4Y+Zb5ffw0MiYMNqT6YUSdJ7X6xDxJND0ZZPQ7SZmoGybXA@mail.gmail.com>
In-Reply-To: <CACT4Y+Zb5ffw0MiYMNqT6YUSdJ7X6xDxJND0ZZPQ7SZmoGybXA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 22 Jul 2024 22:38:34 +0200
Message-ID: <CA+fCnZeZqPX-K=FAAHfT3nZKWPgAABsqKBUrhrZJ-omuyH=w6A@mail.gmail.com>
Subject: Re: [PATCH] x86, kcov: ignore stack trace coverage
To: Dmitry Vyukov <dvyukov@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MoiQKAiz;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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

On Mon, Jul 22, 2024 at 10:36=E2=80=AFPM Dmitry Vyukov <dvyukov@google.com>=
 wrote:
>
> > +# These produce large amounts of uninteresting coverage.
> > +KCOV_INSTRUMENT_dumpstack.o                            :=3D n
> > +KCOV_INSTRUMENT_dumpstack_$(BITS).o                    :=3D n
> > +KCOV_INSTRUMENT_stacktrace.o                           :=3D n
> > +KCOV_INSTRUMENT_unwind_orc.o                           :=3D n
> > +KCOV_INSTRUMENT_unwind_frame.o                         :=3D n
> > +KCOV_INSTRUMENT_unwind_guess.o                         :=3D n

Ah, I even reviewed it, completely forgot :(

That's great then, thank you!

This patch can be ignored.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeZqPX-K%3DFAAHfT3nZKWPgAABsqKBUrhrZJ-omuyH%3Dw6A%40mail.=
gmail.com.
