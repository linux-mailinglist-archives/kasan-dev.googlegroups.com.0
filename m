Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB5VBYXBQMGQEEEQ5WDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A04F4B02337
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 19:59:20 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-32b3f6114cfsf9615791fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 10:59:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752256760; cv=pass;
        d=google.com; s=arc-20240605;
        b=hh6uLJEUBe5bnHBWw1gEEbxVhZ8/9BX7RnnMCYkBzVHaV3BnEzQS7aXA49DNukfJ/h
         kXe2EuhRq059LBS0OIYl6Qz9T1VN4fNzXQbyL/6zsINnH2LfuYRgho3Prpouo0Vw1GjE
         tyz3u3Z869ZZ0Dvoz+pzKQ9h5ltrmfNl5def0xDfbbKO+syAAzAAtyhjrAISKL4xfAGm
         jNYUZYk1ofb02Y8IA1KwrESdIYFS3z7eQq2Io27c/1xPGp+FCW5QbxQlmlFlFgrlMSPZ
         E0bMcr10zKaz1LgzxxOsJNzpnUr74UFnL3/Esc+opgWzpTtV8PL94+z2nwm65ICXG0zt
         9f9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=0WP5ua2vhzvj1N78wROZL/7EG7tygRbtbCnGJuPYAGc=;
        fh=AeY4RoVwV0fZcYP7h6tmsqsDJcwSKBNKiPtSebnMwN4=;
        b=CdHBO7hnnt0bHfmtq3xFOzCHR7j77QO8l96oLZj8RMm18yhfSUrSkNuLTARYMwWZz1
         Lo+yz5+1j6+DIa0SF5eXf2B8/KhuOLN/VqxhgLnd2H3Zt4upzEJ774F7FXbCy2T0PuSG
         6eAaPLI/pofid56FMdwXKQB1qCm1aaO7tVCu+KLXzaYnz7lHNcgo6S7qAEkASruTgny8
         zlkJ6Arzj5wZzRsPm8UA0a+0vUzQFOHDVdoppNFW3/ory0bmvy/JP93XVgnYW4du9q7r
         DqQnlvpcyo2bzlSIMkJOZsD3qhANyJINuE3svCizs8AVIFps5cwWi3EXMXuxPfoyu07t
         rJ3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=EJ3OzrjQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752256760; x=1752861560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0WP5ua2vhzvj1N78wROZL/7EG7tygRbtbCnGJuPYAGc=;
        b=vL9gnGf2JzXrqR+a4Osqmc8uOzJ391Hmjjc0yKKjArkVoMg/8FlpOMu9jh7q0UZStJ
         Q+Vw6Uke2Su1LZLWN4XcW2JpzJK1xoJD8hfn+NpQvntNNtwnGSx79h1+LBrH7iVPm+FD
         B+/2rxjLO8G+F6uIaCTUGUS1l4BsEWG+fz6mm/TEnKraBEaE0fV2kIsQaN9+ASAD3OrT
         AasI3ySQr3xSr1mgzbfMoxl6AARkKY3K9tSqYRea4DHEjx0kpcCoyE/AOYXADo+MDv4K
         yW30VZhReBusMbXLzeK9ABlb3NSzB5A836SZ38Iryf61rg273QskyQt2CzO4tYQR9FUj
         j9UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752256760; x=1752861560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0WP5ua2vhzvj1N78wROZL/7EG7tygRbtbCnGJuPYAGc=;
        b=V4uOuHRfmwaanK0nlMS1A/S3B6IM9A6fTqMB7GmYtPSt4aNHDYVC3LkRN8Cc7UaMjV
         jmOwWjIc028XuTqmPoIWtVkfz9jXKN9G2zUtqmNqkmeDiF2lyNSQ7AQ4qvCuLUW17AO7
         GDG8qsI6W6pUMJZY9mkt6zZcWl94G/90RdFqCAF2yR9NkYIZQYadhqW4iWSEqvjL15I9
         +Z2lH3gSiCwlu4W9RyDmFbPWhH1ntdGRG4dU0B5CIPk8aJmrmwG7iyRh+YCvfjYwRbwp
         4fwn7M12SH8VgYeqkq0MWoH5wdhoh0hFVPhi9VdCNN/Zq9oTFA9Ocsh6RtbWm9oqVzkR
         PqyA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2DfhJbA3T+HayUcZDKIA9B13nhjbQ9sReBFdPo89PMkbK6ONVIq8bo6neDFsV198xoKZjNQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyo5Eisk40oi1xj5yqU5ndPUNxTltt0bUeR1AMCzDrP9tSLzulr
	MeyIIaOsPUXxgrDTVDBTJ60RRESfgwtGWWUFCto7Krsw1OxXi3x8fVgH
X-Google-Smtp-Source: AGHT+IHAKUSbOZYWRsZX1nFr9Tn3nwBiKPINbdx9rNXXEkGJtv3FTGbFU5kW2D7NkzyK62V9kndlmA==
X-Received: by 2002:a05:651c:40ce:b0:32b:7ce4:be22 with SMTP id 38308e7fff4ca-330534384bbmr9338381fa.27.1752256759582;
        Fri, 11 Jul 2025 10:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+PsfI1gVWfyIDwWgc3dwAg6sN122Zp2MiuRQMsVQ6Lw==
Received: by 2002:a2e:a9a0:0:b0:32a:6991:c382 with SMTP id 38308e7fff4ca-32f4fd88ac9ls5302431fa.2.-pod-prod-07-eu;
 Fri, 11 Jul 2025 10:59:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgk76iJJxGUZX/ZWYvqgnZIIFgpWP+2xbh8pXW06EHuykXIAA+tjltABMvInqtuDfnnny9fQ0krxc=@googlegroups.com
X-Received: by 2002:a2e:a016:0:10b0:32b:9792:1887 with SMTP id 38308e7fff4ca-330532d1b57mr8045581fa.11.1752256756053;
        Fri, 11 Jul 2025 10:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752256756; cv=none;
        d=google.com; s=arc-20240605;
        b=j6zQOeTJxE8b1JdCH5zC8P6zSTjcyQ8dT0D32lpl1ydnl+gFalYJQqPHZqfSx6UYtb
         X1xrPqGWuqpSGsfxjvMMQln4XWHGCN1KNJYOPDAKAC1C5Nd5gCyutxj8mSkZDqNN7KkI
         DQHBk8bZaRoFkJrWKzJ18N59pqavnGj6TQOK7YoKG4YLJKECM24fgWXt2/hDWfaTs5np
         LenpkGt8XRmkJ+zoT8VcjDxXc3O6lNWvXHe4BvWE6nLBje7eBG24msAeOVkwytn3LEs1
         itUtJVVpsbsUCa+8aEh1NEMnYVlLRG2m727A/OmA7lYg5Si6BA+BfQZUhRW0hehi7GYU
         Ch/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HO86Lx8//8hSyzYLerKKeVnItqg9SoMBkOdjNB0C6us=;
        fh=s/CkqbFmcY+V8LWss045bE5WHUiuMrm9SvmBO3VITVU=;
        b=jIL28cE2aRMG2cqVC7KC9knU9ZBbdifOq45r0i5eQmhgoiC3e2ZrFYGDLC5tgVQcBG
         TH5RWAsj9m64LCV3ehWKaW4gSnEvGpaF8rHGGAv192wjzUle3Z7KjVol5gKjXcWcRrtr
         VX73AAT7e46RI6T7xQcJ15iflspFbgGyOa2RkKdXMFVwqz2zXWGiLwo3TVQt1fYQiu+e
         cOQEfGrEeBSyYJnvYQArnva/hV4qkKHRdR5YXSSrZSVR+kt+BNrw0Q7EytJ/KQEZJLa8
         LGui+Vr+3z5nO1cPE7MetoVObJag8F3Ehbp1ERRFTqrrxdzylqwdEgS/I42qOx2gWDUM
         Gqrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=EJ3OzrjQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fab84abcbsi108921fa.7.2025.07.11.10.59.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 10:59:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id a640c23a62f3a-ad56cbc7b07so418439066b.0
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 10:59:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXpQo66/QE/7qsRFzI+s9j+DW+QesHQ9sgIDZCt4EExq5DA+RHye++RwbYiZ4VRuIRGsjD/gSnSwmQ=@googlegroups.com
X-Gm-Gg: ASbGnctqXCsy1F9Wet7UbCOyk7Xj+QXg+pi3iljbNvMvb/THZKg1QuXPlQlV2exOzzN
	mUszY7WkWRDLft7uFDtzFjHm8TKvSG6+9yguqTWwyRssnd4Xf/6+QZ9pMTsNQOOdeA/3Wl9g342
	DilR5f6Isv6otQpBanVlwviBY4/tML3MxPcJGipdj2xVsn8Rwgd5LMFuImCtEBr+/kFNPwfkSo/
	pNN7po3eybuFf6o8ybFFMtsRhtkj+YOoCIOEl+WOUWz60cUxGdbe4iZQ75dV4aUnSJ+KAzZlbyn
	+bbjU7vcG7FemA+cVPSVAzeco21lS9F8jcCZEDwbeTfRbNGvgtaHTjPVUcRRjg7n0SaYwhybuP0
	su1VIYLMUjAfzfBMO4t6F0l/vxZ5Gzi53ocd8DAKF1gYfHtgXJG+g0HFsVnikhnB6co1o1FMV
X-Received: by 2002:a17:907:3d8e:b0:ae6:f670:24f2 with SMTP id a640c23a62f3a-ae6fcad294cmr474257166b.47.1752256755307;
        Fri, 11 Jul 2025 10:59:15 -0700 (PDT)
Received: from mail-ed1-f43.google.com (mail-ed1-f43.google.com. [209.85.208.43])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-ae6e82e3a80sm333672266b.172.2025.07.11.10.59.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jul 2025 10:59:14 -0700 (PDT)
Received: by mail-ed1-f43.google.com with SMTP id 4fb4d7f45d1cf-60c9d8a169bso3970930a12.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Jul 2025 10:59:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUJEYehBLctfB7mA6ySZ4bZlaf2qbQroToN+GqynyAZVme9/CbOrrJ00gUAs5K9RhVN9D61DqOLoM=@googlegroups.com
X-Received: by 2002:a05:6402:518d:b0:60c:40bd:8843 with SMTP id
 4fb4d7f45d1cf-611e764f6e5mr3668397a12.11.1752256753054; Fri, 11 Jul 2025
 10:59:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751823326.git.alx@kernel.org> <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com> <20250711184541.68d770b9@pumpkin>
In-Reply-To: <20250711184541.68d770b9@pumpkin>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 11 Jul 2025 10:58:56 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
X-Gm-Features: Ac12FXy_-gvqQgEDwxrh9_yUhPGT4NZn2yvYc_wfrsBVUNUS1D4_tzcLfdrYbJI
Message-ID: <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
To: David Laight <david.laight.linux@gmail.com>
Cc: Martin Uecker <ma.uecker@gmail.com>, Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=EJ3OzrjQ;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Fri, 11 Jul 2025 at 10:45, David Laight <david.laight.linux@gmail.com> wrote:
>
> What does that actually look like behind all the #defines and generics?
> It it continually doing malloc/free it is pretty much inappropriate
> for a lot of system/kernel code.

Honestly, the kernel approximately *never* has "string handling" in
the traditional sense.

But we do have "buffers with text". The difference typically exactly
being that allocation has to happen separately from any text
operation.

It's why I already suggested people look at our various existing
buffer abstractions: we have several, although they tend to often be
somewhat specialized.

So, for example, we have things like "struct qstr" for path
components: it's specialized not only in having an associated hash
value for the string, but because it's a "initialize once" kind of
buffer that gets initialized at creation time, and the string contents
are constant (it literally contains a "const char *" in addition to
the length/hash).

That kind of "string buffer" obviously isn't useful for things like
the printf family, but we do have others. Like "struct seq_buf", which
already has "seq_buf_printf()" helpers.

That's the one you probably should use for most kernel "print to
buffer", but it has very few users despite not being complicated to
use:

        struct seq_buf s;
        seq_buf_init(&s, buf, szie);

and you're off to the races, and can do things like

        seq_buf_printf(&s, ....);

without ever having to worry about overflows etc.

So we already do *have* good interfaces. But they aren't the
traditional ones that everybody knows about.

                   Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q%40mail.gmail.com.
