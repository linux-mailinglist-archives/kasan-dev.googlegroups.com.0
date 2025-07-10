Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB4XTYDBQMGQEHDMTTTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E854DB00E80
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 00:09:00 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-553decb7e3csf720450e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 15:09:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752185332; cv=pass;
        d=google.com; s=arc-20240605;
        b=klJSXI8+l8oJkNlDhRfU5hEDPcIYIK0EsNHxdP22u/8yCmTBK80RFgV33MMZ2UMBtR
         g0zW2eJ3nosA7bHk56YIpZaADIhBzP5PzaJ8i2M4YNV8hAreSqB8p+vgCHefmuUQDHhH
         Xj1RMYdFiE7QxtPJewnwlN4TmCeOkE9HahVVHtKHuSoA+yXuf00vZ8wk7HO3+K6DMctB
         9O57ww4agsrpoRNFTtiqr2iA3E/wZiGbtvv5rHFqGVlmtuZgoJzT1kstk38eA/9Am+rQ
         pU8AcVzymok2rT8pTZpZa8P4kMtbpJaA9JkDBn/t637Cn7FiyRqD1UnOqHkXrA8C7TbN
         sUhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=JmsWCPCjdCRg+rEV50fxDC4wL+XPaTLc9gPaYoj8ab8=;
        fh=DdgXJxxTnL5Rl/rjWQwnRLEpRjNWYOjQQev4X0uEqUk=;
        b=eCdnkp+G6ztGp56OsV4WCcDcx9OYwxsdig4/5JP9L/1SwfVnmidoBIuJX/U00Fizdo
         rygrlk+0CjkmKTQHDyzLoyYPDsDBPMF+86ZGuZ2dy0mQFimFcTPx69uMpKE9OpX56ZNv
         IT6KdgdAwcnk2TiyZB/3LzrG19XYhUB+PHvUE/Az3jrX+gcQ96Wp42W7I5I9uvT3QQiT
         s+yBRs9td7RP5lUnFeCc56/yRBItI7SGFtyWTW8Kavta6cDHHAEji0paF0BiPAl/Igh+
         apuvpg9mszliiIh2gLVu3SNBh/8LyWJVAKwy5/7rr3wnX23TYIZZpbKqxGh5Wi8/LheJ
         daoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=UtKPsawe;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752185332; x=1752790132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JmsWCPCjdCRg+rEV50fxDC4wL+XPaTLc9gPaYoj8ab8=;
        b=q/h4KL0ELhjMoSo6CBLE8TZxoNvHYlen5JRk3NKR5lVYm6+1yCHQkbkD2uNemdf9c9
         N0CKtMToG8dlam+H+bDJeFs3pVviJvCu6kritGDNmh2LKbmHqa4euIkByZCoLopWP6MI
         AlyuvLoRAVILjavGc8riBhl0+SspM7guflKnUD0yB7opZGNr6i6bUf0cfY5DOf8PIKFI
         a3QYYD+rsESv9GTrsUKSnBvsfFk/BdNrYRT9GR3tB9ub159U2mvsqPDow0OIyiQkJ2e4
         Y+c3l4DioNud2Rk2c6qwcsrXi9o8G4rKoLEh4J3aArFeTeto7Afwkp5EmsjqUW4ctVZg
         axBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752185332; x=1752790132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JmsWCPCjdCRg+rEV50fxDC4wL+XPaTLc9gPaYoj8ab8=;
        b=fT2HNEkD4OkhLwj9LAvwBiPcG7EZqBsoc0OgcY+CGqGl8wWD+uVzvhVFOzzAia097J
         gl+vnevKWqk9DWlcDGnboTGho6d77m6m+qCp7bHZ9HpJom4TLp/Us1Lzu0Pnck8NwLa+
         yhmZxaWPjuvzci+ECnlxNRjwCskoBN2ctrG2bvG/xhCsZoWdMYGYJkYa1S0bsc7lb7on
         mjUP/lWYlxuUjx7WfQ1NAkGc5TpFEkH/y6UJgGT1SedlTu45O1dPxwNQ5rZ/Luyhkz/J
         dD8Of4DhBaEQOZ41rzT4RgOUffnQwTfx/GtgIfPKvnEUBIz52fowG+3uxydI0kwwmWlr
         Cn8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWg9IK80dqq9fX2oOCYyTGRX1a2tmiOtO8cWIE5UhLEwIUK4KGZxa4a8Y08BO1UdaZHvk+ZOw==@lfdr.de
X-Gm-Message-State: AOJu0YwD5mX0VEU6VtjTuP5uK1LG252PnGAVrdKB756cUTeJA2uvekp9
	WfgBEfpZZiTZappf60kmfJg2xJqxJJzlLbcY8NLsaVIEaMddRpugIMJS
X-Google-Smtp-Source: AGHT+IGPxvYPBSSerdjrTbLvkfAi3FmAg3jfP/5j7QaMqHG2nXUkJIk4GSl5p/mP86YFmjnyacnNjg==
X-Received: by 2002:a05:651c:19ab:b0:32b:755e:6cd3 with SMTP id 38308e7fff4ca-33053659634mr1309621fa.41.1752185331325;
        Thu, 10 Jul 2025 15:08:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfb4XaOhtr4czArIk0XcwEcsCu1JwmLzPcP5q9zZXUXxw==
Received: by 2002:a2e:a495:0:b0:32f:3f93:212 with SMTP id 38308e7fff4ca-32f4fc45551ls2088821fa.0.-pod-prod-02-eu;
 Thu, 10 Jul 2025 15:08:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVp+EWwd4iQsC/L14A7W6p66qj2Ku9Ta8x4a5gdpQyNTC3WMr5/tLJHzu86wefoTgf/sEz+acpe1U=@googlegroups.com
X-Received: by 2002:a05:651c:41c9:b0:32b:7614:5745 with SMTP id 38308e7fff4ca-33053499eb6mr1326451fa.20.1752185327898;
        Thu, 10 Jul 2025 15:08:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752185327; cv=none;
        d=google.com; s=arc-20240605;
        b=bEHn88WV1Znkfk52ji0NABT1nEwWGD11E7wOUWiC5+9aO+p5Xu6DZZZuvW3tulMG2m
         5meUZCOUv0h0/ttRfrSrwbpM32Jx/rIaBw6flA+HakG3mQ0U+LX3XS903UhFiLGs5yS/
         Rr5KEIvV8KAR9gKBJ5OYXOJ8EggEgWfQM/nCbnRQ6PRegMs8rvftXHd0COfacuUprCuU
         n4sXjn0jrlPQ5+i4a/1wdzPsSAzAOSSBh/Wed1xhBEUpbrT48rHQXcBsvE7pTLZdMiGW
         /FlVZdEutyV6d1iJy+1EDiBUSD9KNPASKdok7wSRyJd2NZVKVj3rGEib+06iB/f1J/V/
         6wOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ykdGKGKuBHYeQ543548mngZ+AURoPxGnuzWJOvHPANU=;
        fh=KZOXap1QUz96EkN2xotJjBaIpYnoq1Xoi+hQxVAE6Wo=;
        b=kCBLAqUlSlRqw+/zxczXTCj0/AZFehAtzpkJxl050a5g3vGJ/AqBAycQ+aRltAU2c+
         cdkLmz3zfG3xwAxZ4yyaBGxrVh8o1AwfCfYvLCiKTGli4M9PoaPaoeaN1OMsHGC6+j/2
         rerzK+dLlGtMDZbZwTH1ID9QIyZ59AhCv2vmir6fEi/MLskqVN1Uy3KBxkylxLsA39ym
         RmRHk7isD1CJg1FV3J2VpS4b2Z6/yyWIcU0OwEql9EVy5crBDhmZhFxvM8ebWl66XDE9
         FR9FVIF/3bBZx3b/29IeWBMb2OHiJBNVQoTPPURMQpz2wkoESOoVeHxvYxoaN8RtLZes
         gBcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=UtKPsawe;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fab84abcasi501211fa.7.2025.07.10.15.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 15:08:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-ae3c5f666bfso250541366b.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 15:08:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSk8sSl+SeZyWaRaCrrwJfGGYZG+bbTBuJblrjQhiC75n3tp2i+BDRlV3OSOFF06FNsOh7KkxHmR4=@googlegroups.com
X-Gm-Gg: ASbGncuHe8EKof0Bv9Waq6nkpuiSBaXwWC2rTIWp4ANB2YJrElXlQEtCJ8usxDyMMRh
	5tfe56BuRrAoO1wUBxDYYjrYiGc9mZwB9oL1p0eBuz2B/QFZp1oJWLBWMrjgq2QnA7P4WU+NT53
	RXT1OxJOxVLoYF2J6dmbWsho7eTNhnfcrmzN5b+9D8zOBqm9UtdosConeb+OTWYpcO5BKv2DUpt
	XfNSBBT2CuodP1Kup+QY+1xiHrvuuBcSR5pV+9QeFQhOaqWBarjjuvoskcqEqFLR/orjiThkxFa
	+U/DiFyR9Bc4ve4OM5w8WF89jRlZXPAQxO7/9Edz2QWHUpqvIzewxjRc/J6Af7ErildHCJUZpM0
	FIfoSitVjfituqIZO2y4QsxpNTj4UF14Q1F8qKlw2YOkI2DTrkqnNqvPAx7MxviG05xgK5AIE5G
	S7hQbr+kU=
X-Received: by 2002:a17:907:60cc:b0:ae0:67ae:f8e8 with SMTP id a640c23a62f3a-ae6fbc23522mr90005966b.10.1752185327128;
        Thu, 10 Jul 2025 15:08:47 -0700 (PDT)
Received: from mail-ed1-f43.google.com (mail-ed1-f43.google.com. [209.85.208.43])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae6e8294008sm192483166b.124.2025.07.10.15.08.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 15:08:47 -0700 (PDT)
Received: by mail-ed1-f43.google.com with SMTP id 4fb4d7f45d1cf-60780d74c85so1973340a12.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 15:08:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV5flFOZzsMZv/qGdKZWrHTf0SJ2D30+hD68J4rtZhxw1XgLKvDNnEcW0n8QXH2JCM92oGWTOXeK+0=@googlegroups.com
X-Received: by 2002:a50:cd57:0:b0:607:77ed:19da with SMTP id
 4fb4d7f45d1cf-611e7611808mr397182a12.1.1752185326316; Thu, 10 Jul 2025
 15:08:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751823326.git.alx@kernel.org> <cover.1752113247.git.alx@kernel.org>
 <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
 <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
 <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq> <yxa4mb4tq4uamjc5atvhfefvxyu6fl6e6peuozd5j5cemaqd2t@pfwybj4oyscs>
In-Reply-To: <yxa4mb4tq4uamjc5atvhfefvxyu6fl6e6peuozd5j5cemaqd2t@pfwybj4oyscs>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 10 Jul 2025 15:08:29 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiOSRbTqEO8H=5bBem4Su3E=bZRLM3nE5rwLHSofhD0Lw@mail.gmail.com>
X-Gm-Features: Ac12FXzpHETNg-HuLSmnK9b1Tp10RJ2FzmkvjWu0i-rRbR44n9d-UbbJBC2bj-w
Message-ID: <CAHk-=wiOSRbTqEO8H=5bBem4Su3E=bZRLM3nE5rwLHSofhD0Lw@mail.gmail.com>
Subject: Re: [RFC v4 6/7] sprintf: Add [V]SPRINTF_END()
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=UtKPsawe;
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

On Thu, 10 Jul 2025 at 14:21, Alejandro Colomar <alx@kernel.org> wrote:
>
> So, I prefer my implementation because it returns NULL on truncation.

As I pointed out, your implementation is WRONG.

If you want to return an error on truncation, do it right.  Not by
returning NULL, but by actually returning an error.

For example, in the kernel, we finally fixed 'strcpy()'. After about a
million different versions of 'copy a string' where every single
version was complete garbage, we ended up with 'strscpy()'. Yeah, the
name isn't lovely, but the *use* of it is:

 - it returns the length of the result for people who want it - which
is by far the most common thing people want

 - it returns an actual honest-to-goodness error code if something
overflowed, instead of the absoilutely horrible "source length" of the
string that strlcpy() does and which is fundamentally broken (because
it requires that you walk *past* the end of the source,
Christ-on-a-stick what a broken interface)

 - it can take an array as an argument (without the need for another
name - see my earlier argument about not making up new names by just
having generics)

Now, it has nasty naming (exactly the kind of 'add random character'
naming that I was arguing against), and that comes from so many
different broken versions until we hit on something that works.

strncpy is horrible garbage. strlcpy is even worse. strscpy actually
works and so far hasn't caused issues (there's a 'pad' version for the
very rare situation where you want 'strncpy-like' padding, but it
still guarantees NUL-termination, and still has a good return value).

Let's agree to *not* make horrible garbage when making up new versions
of sprintf.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiOSRbTqEO8H%3D5bBem4Su3E%3DbZRLM3nE5rwLHSofhD0Lw%40mail.gmail.com.
