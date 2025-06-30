Return-Path: <kasan-dev+bncBDBK55H2UQKRBMMARHBQMGQE2VRFRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E45F5AED5F9
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 09:43:49 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a503f28b09sf2080611f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 00:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751269427; cv=pass;
        d=google.com; s=arc-20240605;
        b=bDUuGjZr298dUHpOIhewvOv3AAPNgs086vFTo6MQ/ylAikaZ8JUOBDEMBdMp/49jDS
         SNFzkLGLkUr3F4WPUPLRXWqYZAt6D4w5fF/oDfEo+Tf5oVaR+hizPK2LrEo1RBIFTF0D
         /SW97txdatCvNOTHtqJB23BNhNEHwG6IDLWjGoVMerzUYdJt6/1t1cDBi87l+Hxk/Unk
         c8A/Nb3uYJyQ3OOeJC/+I1PO6ELQhsh5kPofwpulrtT9A7Z4TUMz4zkcxzdoz6WhLV9I
         jXhitHs0O+sJsASUZ7J6/yb9rvAblcZQHiLm+0+avB/yCVKO6TcZsWqZAr6uIS47j/HU
         RNVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YWrMzKugtW94z0wa5LkgJaX8j+NNE0eCvvAuu51k+AI=;
        fh=xx5YS6TWC0m+V1Jd3wINHmFNvqMRI42UDKMAMZSacEg=;
        b=K07D6AqYKpHIGD/7vuos6g1L3UAM3n3jcFSpBRcyEK2n72dqGpAraq/Xq7osgVdHdG
         d4LNiX4INo4FX5jQQjZILmIRM4XS07rx3wriWaC5VDoHzmulX0znTUBy1LtnwDeUW52E
         l124YANWTbCh03zAxRhTDhqCUcSzbzJoZg/X8m+Ot5yx6NEf8XhePZ3xZh21spRRxW5L
         n7Js8/XqesPkHIJ+aHXqdxYk3pKU1DY/6MLlfb+sQ++l4BSvQ/E9H15SfmEwzCrvw4zZ
         J/GH+GMwAJed3BUNg/d4bksRn80NWbs6XZ3MmXeK64rrYN6gGexN+s6cBkN1xTR1j7Px
         IorQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=RxYbVixa;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751269427; x=1751874227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YWrMzKugtW94z0wa5LkgJaX8j+NNE0eCvvAuu51k+AI=;
        b=bq9FPCbBuoNubyXf8pWZdjnA1nWaJ1YqLi8z9fdXZFcb2iT3p7YTn3e628QY4wOFbL
         K9elqmA+cceoOtFwJxX6j1n/3/JeI8UDngwFrtop3pCW0ATHEyj+e3NfwHpIMax3N6J3
         hV3cpiVkDW4cPFlvVaiQRJcz2iC0Glso9yE7YwffYLQaGRDYspQKmZiHyLKa1JxefbY6
         NpaGRTMYBbdv5uMn+35Iwg5l/lr7g9Ss7QPLrG6vo2rkXPDMEkxgJGtu77Y9JnH477zf
         cXGIA3HqL4uXZa/lXqcWfo81/ZbhGQCBQVV9pc8OdwQ8Wvj+yG9s+AVShGXARUz6u4Vl
         zVOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751269427; x=1751874227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YWrMzKugtW94z0wa5LkgJaX8j+NNE0eCvvAuu51k+AI=;
        b=EVo5Kc+TJkty/v/m90TRkqgzcLqvdvA5g/UkfZyabEOVKN9F4Td1DuHznNtRP1k7gE
         jECebR7GRfN/Se4cm7hsFKb1FLrpCJGDETUI8y6+FISQgw3J4g3DrY5LR57C1AHaNXB0
         e0qZTfwpaO6twYKzfQ7O8m2LzVRiujLfwKTJUchHNYqUT8IvrQQ1EydCMwePpL+Kvttm
         a5NTroEgKRa64cQvGTEYy9CsOSs9H8CsM4koNESIOXppCcy4CVBT4esI6/KcUJCcvKHG
         gBpEREepUoxUCz4b88F1BKt0B8t1mhANaGh0F2BjD/prKUMw7F6yaeLmrFj33/QPDo3n
         AOLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVj0o72kmweIcOaP8tloDyEyqUueis+RIkZkKl0ws0D2aoiD36qaFrA8mIKVUH14dxV+cJfw==@lfdr.de
X-Gm-Message-State: AOJu0YzmvLfttD6j1BmiFSiuI8c2/FK5Y32riE1fUfTxZ4lsd9EhpZu7
	Ll3Gaz5wItnFNHB2YGU334y/BaWxAvUNuwVOFof3ldXiZWDTM+hnk+Zg
X-Google-Smtp-Source: AGHT+IHN7JK/yXTG5/6E4o7z5MGU7vanlrZiKQpuvGfA/4j1Ewn6QcvodvquAnIbnnH640BEw5QxCg==
X-Received: by 2002:a05:6000:2d87:b0:3a4:da0e:517a with SMTP id ffacd0b85a97d-3a6f31535c9mr12856447f8f.23.1751269426412;
        Mon, 30 Jun 2025 00:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeIv/raaCKWYwDrdeppw//AMLouqOo0rx9o4y+ZQxtPZQ==
Received: by 2002:a05:600c:3545:b0:43c:f636:85d0 with SMTP id
 5b1f17b1804b1-4538dbd3383ls17437475e9.1.-pod-prod-00-eu; Mon, 30 Jun 2025
 00:43:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJtm+pKP0kbCXpiEZPUUbrNAxdArmQVf0r9EGaeHOJSuJih6qj1SDtIRZRt8tkWHGW1shvo9XldA4=@googlegroups.com
X-Received: by 2002:a05:600c:1c0a:b0:439:4b23:9e8e with SMTP id 5b1f17b1804b1-4538f2bfab9mr114464765e9.3.1751269423249;
        Mon, 30 Jun 2025 00:43:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751269423; cv=none;
        d=google.com; s=arc-20240605;
        b=I1RLBaU+TD83jBob0docpWqgLjOAGnVmiToK+X8AZm6KzONJtixQw1YVUxzH27n0P3
         fxaVZjo8dQ5TENOCSwOpKPU4D01TfiXCkQk9wVvxQQ89fiqdAcQCAoMhbEE33EGJHoL5
         RUIkoLvhJ2h3VNezBxSY5nMJmVzZ0PQcVBnv4NHIEzt2Jb/G5p3xFsvn+z5/avQzSst6
         qP510KBjzk1cvA1E9bo/cK88nlHAsudZ23CU3i8N9NQW8hvIDPwFeqQ56/3+yY8Ggxjs
         l7WhKsN6bhLTIrFlKOCl+mVGagev6ywsA8dmmw9r5QzvhzJd9cLEIEoEdMooKtDPEvz/
         tuJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=dZfCzIqS0Ptn3nr+ORDa8qmkAF49TPrkMwvLYPx4ASQ=;
        fh=Ek1jAUi3GNl8SEwqAncxOvAsWJOejJFeI61Czi5lJC4=;
        b=hJbegKGpUeA2b65sNSGLT8AQJlAnq9grhHpIyeiLwuHM9dmahcql/okmpWzy+R+IGd
         OuOXtwvHBvRwWQ5SU8JHfWfnhIrFZKDDmPNKWd1HW/kedYr2zUJ+D1RoBLTEBihQqmyZ
         T0Rpu6unHXOHDSuAXisBUTF3eT5reW+Ukgbf5Scl8QXrPpKU615jFiU20bvWBXdZ1hvB
         0qAQ6NJu3wcbUOl+UdfF+US9w3hgiUh9SNWJxI1apPyowulGmrpMChtHC+kUwGWTVyv4
         SoAUkUstXT4cnIbgFMostkTYCXJ3QnATY9vnTzEog+vuYfFUhYIrs1MYyg0ppzWAfv2B
         BzVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=RxYbVixa;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a87e96a387si567694f8f.0.2025.06.30.00.43.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jun 2025 00:43:43 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uW9Ay-00000006k4c-3Gmx;
	Mon, 30 Jun 2025 07:43:41 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 57ABF300125; Mon, 30 Jun 2025 09:43:40 +0200 (CEST)
Date: Mon, 30 Jun 2025 09:43:40 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH v2 01/11] x86: kcov: disable instrumentation of
 arch/x86/kernel/tsc.c
Message-ID: <20250630074340.GG1613200@noisy.programming.kicks-ass.net>
References: <20250626134158.3385080-1-glider@google.com>
 <20250626134158.3385080-2-glider@google.com>
 <20250627075905.GP1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XvYNkRp00A_BwL4xRn5hTFcGmvJw=M0XU1rWPMWEZNjA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=XvYNkRp00A_BwL4xRn5hTFcGmvJw=M0XU1rWPMWEZNjA@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=RxYbVixa;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Jun 27, 2025 at 12:51:47PM +0200, Alexander Potapenko wrote:
> On Fri, Jun 27, 2025 at 9:59=E2=80=AFAM Peter Zijlstra <peterz@infradead.=
org> wrote:
> >
> > On Thu, Jun 26, 2025 at 03:41:48PM +0200, Alexander Potapenko wrote:
> > > sched_clock() appears to be called from interrupts, producing spuriou=
s
> > > coverage, as reported by CONFIG_KCOV_SELFTEST:
> >
> > NMI context even. But I'm not sure how this leads to problems. What doe=
s
> > spurious coverage even mean?
>=20
> This leads to KCOV collecting slightly different coverage when
> executing the same syscall multiple times.
> For syzkaller that means higher chance to pick a less interesting
> input incorrectly assuming it produced some new coverage.
>=20
> There's a similar discussion at
> https://lore.kernel.org/all/20240619111936.GK31592@noisy.programming.kick=
s-ass.net/T/#u

Clearly I'm not remembering any of that :-)

Anyway, looking at kcov again, all the __sanitize_*() hooks seem to have
check_kcov_mode(), which in turn has something like:

 if (!in_task() ..)
   return false;

Which should be filtering out all these things, no? If this filter
'broken' ?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250630074340.GG1613200%40noisy.programming.kicks-ass.net.
