Return-Path: <kasan-dev+bncBDHIHTVCYMHBBW6FSHCQMGQEW56EN2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7654EB2C0B2
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 13:41:17 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45a256a20fcsf13330175e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 04:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755603677; cv=pass;
        d=google.com; s=arc-20240605;
        b=T4myVSEla1+csTXS37GSQy5r+rYrMEaFTSX8V+RPq0KvGyy2xqooHssmkd/nntlMTZ
         EEdNxOzjcqzsrlAQhLSa1ZpcHKXgxhZ9nNnw54ofjLZ1W4gBAsxVQM12m+2aet0cxwLj
         TDCMLmK4RX7tlsHE/NKAI1n2liwt7sRjppEHWV7Ih7LqiMW9WYvUzI7XRtWzQalH67C8
         EM8wDzjDFXs0cB/F1KMqGDOwzn3Ab9L1eklMfQbehZZfsZ2nJdzvQ1RcrgcublDW8rNG
         jPt6nGVJvXr1VVpXil2ZInnw05+DtoaXye+Fnu0Vjum1n3iolpM/nChPJJdmJdekaxd4
         qGVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ukoziLM/Y4+1812ZhVdKj1AWkwPfLPXMrjsgOZ4B8EE=;
        fh=9GnWiEwlQTftx+wBgDAreLH8ElH3x5nvnhG+6FK776M=;
        b=CeNzjDx8t4uPUs2LY4kKZWB+XVFNlz0uyAOn6VEy4eg1VwJ2fpNWqJ7g4E1JNxCwhN
         fpt2FF/2qIhCBLrf6aYoqfGq6b3QxZiNWwgqhCtpuDIjlDSbM1Nzywhb3OXJGQ//u788
         oJwKt52eEbP4XHNWw5XcVSukPL8U81seXfttmaNkfJ6QmCJoCag/MW11GhVqU9XVMfrD
         SoDDSXnk/c/K3f0LSi39xApX58+quurkYsbLfgreQSrZXqwT60nWQVzzijveUQyRctKU
         p2jJ8NQJauGXhlZq9OQwB8ea4qL1ji4C4k0vM3vWaZfUS9rfTjiuGlSUU1KBR1iYNsCx
         Y/+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b="A6nS/oc8";
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755603677; x=1756208477; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ukoziLM/Y4+1812ZhVdKj1AWkwPfLPXMrjsgOZ4B8EE=;
        b=CfVqAf05LgoZ3ay4zphnF5a60siPx24DNFAVun0UBqlptDIhmi/NLn4TEe7+IrArO6
         ykRh7CadjypHz13fI8W7ZS+VjYJP7mOKyYgs8rviRUTPGzu7zE1dtYWnBt2jq+a+tj8a
         5JN5I0E2+u0aYsNkbbC4XMTxRJqL0e9Lt6Nu/DUt19JRQlttK3tOXPVSVSDEHq/3fQuI
         shng36XlHEOlU2RDL7epuMKtscMDbKRCEE8itB5OQnPfi/DCB+J6UhNImaEq4L8/4hN/
         COM8Kk5iuIKvk5I3gro6KC1KXvtr1W6Ndp3MpKrOo0+hYfROLZ2sbkWPJIH37aI0vU9s
         BdXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755603677; x=1756208477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ukoziLM/Y4+1812ZhVdKj1AWkwPfLPXMrjsgOZ4B8EE=;
        b=nWJ0TUwOknQpGmyH47HIN/h5OksY3V/Cbsc/Gs9XMogfAWShozVgi244cBayRRBJSV
         ZN3EyLfSpKsilMA63V3xMxGDkyRI+f7AqZwSUGItCo3FK4/9L7LYJ81uaGyLnkh2wry7
         7WO0C3BEzZNT2AV7FzxJIACKu9ib4S4w/rAOplpEUjz9Gm+KQOwbib3UHTzyxL9pFyb2
         ETiiyvBRYr2vRLSfbL1VounMqRes6pWWVuKFd9nWG47EcPzJ/+Biz8DZBSFj8JgcIT9l
         iM5Dacn2kvHW/+nXdoc7blYLWCu8mNUbWHJ8Zb/JnbYK6TrSaUWoSQpLUcBelUyu5nZw
         n/xQ==
X-Forwarded-Encrypted: i=2; AJvYcCVVlwGE+VoqW1prU/elBNgnt0wo7EuMcha/pmgYDAMWN/jbCNk7+uLzIh1Zw9ICwm0OP9XEhg==@lfdr.de
X-Gm-Message-State: AOJu0YxC28Xcdj1HfeaYHTPrGy9lv/nPebZPkmyRO9v9lDDajy/lBtqf
	mjLDhKH0oMMCevqDaFcYkPRZWrX+7wYBhE4j1zUfSvnSZ7PZYae60/hq
X-Google-Smtp-Source: AGHT+IG2rVW55hbOQIgPcFesCyYMIoO+GKldpaBH4IjPxUVtqm5vP+gVwzx/+FxQv4Ihkmg8gDLbsg==
X-Received: by 2002:a05:600c:1c1b:b0:459:e370:d065 with SMTP id 5b1f17b1804b1-45b43dd4dfemr21558385e9.15.1755603676522;
        Tue, 19 Aug 2025 04:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZesjM+caCK0te/K9ghGl7I4zs3kCnh1O7JhrMiEn3CssQ==
Received: by 2002:a05:600c:45cf:b0:459:ebdf:b560 with SMTP id
 5b1f17b1804b1-45a1ae24ca6ls26640865e9.1.-pod-prod-04-eu; Tue, 19 Aug 2025
 04:41:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCGrA+BCKoRI4b8VDJfC3F94VHglA44SUQ0vo2UCXOMj6tnm7pSmOeGd9h3VeIA9qrerDMJI20Q/4=@googlegroups.com
X-Received: by 2002:a05:600c:4ec6:b0:450:d4a6:799e with SMTP id 5b1f17b1804b1-45b43e06ec3mr18538695e9.20.1755603673093;
        Tue, 19 Aug 2025 04:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755603673; cv=none;
        d=google.com; s=arc-20240605;
        b=WHQ6sKWIlD79YUhVCy00qUh6G4sTjM2Jqu9g7P+wZwJdEaqrhX59E2wQvcel+V8ekP
         1ZGf3Q1r996WVqrvtN1Bw1ZvbpSqTbSyc1VfYhaMQk2Xqo5s7nQwbatgsK9xwL6jmlmS
         eEz4UkTIvQf9umelj5XH24z2YMyMRIrXeMKSrIGN1HxSoiiczW5kz6aP9fYhITaSjQ8v
         TC2S7fEl4P9Ub/KJynEHQddFb+ygAcFX3EKZKJC9i+sdhtGRLYr7aXIY7ySJ013hQqtb
         Zj29pw4wOI/Y+FdLnVxza2N7kgCeAwM60kDQipdH9KLS7jCQA9C+Lr3GC2QFeE+jRgYJ
         drwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Tuib0sswv+oZbbdQrooeXCEG/zbTBeXmUDDIjBMwhc4=;
        fh=I9qBf8zkkxm23E0nyrzXUoAN+8u4wKG64IAm3XTqrx8=;
        b=S0ORleWOpJ4Xwy8Pn6yeMuCVozl19wjMMhQ1BzcRt+j+hFyn0WLMXUZ/SlEUSEQJsv
         jimNm/ZzoGnNkGSk6yF94uOusUzrgs2U7FhAr3lHyxZHBusW2Yz7bAPvLLqt3vryPjsD
         1knFG5isV2RA2j5pWEqgDz07F2l/Pwzf+FMWpUjcf1E8ATddmRXOtbTRqKB1JQp+8MCE
         qEi9JrPu9HOtn8BEd8zpRRZ5JjRnRC9E81h7qBCfDbSKP4cVd7tLjwxtcqaBWNtJzcYJ
         JLRedIw4Sgqdh46qGTB051IR35tD3XYUSSnmhAWlbj4+XvNfoviYQV2yJOeut8Buoo4R
         RidA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cloudflare.com header.s=google09082023 header.b="A6nS/oc8";
       spf=pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22e.google.com (mail-lj1-x22e.google.com. [2a00:1450:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b4371b0basi154015e9.0.2025.08.19.04.41.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Aug 2025 04:41:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of ignat@cloudflare.com designates 2a00:1450:4864:20::22e as permitted sender) client-ip=2a00:1450:4864:20::22e;
Received: by mail-lj1-x22e.google.com with SMTP id 38308e7fff4ca-333f8d3be05so35797221fa.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Aug 2025 04:41:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVC+E3aTiJHDHh64n1z7UanIZerFaANhkehKehh/e2X73mI5Cz5EHlyNd0DuAvZeMvwAaYkxuUUwbI=@googlegroups.com
X-Gm-Gg: ASbGncuNCptot1qEe9S1sfKXv++xcCAES7sMsK6qWCz2biggVA38aFA5K6JsqwJK7ub
	m6tkf98fxdg5bKR0PsSFAjwLlIqIZkIuFYqGgHx7kman+8eTg3Jnmjo1+emBBACuCxI19ZNEmDy
	hMg7JYV0a736M2H2hSTfNkC21fPWUXRyBxrZvoQVzHIJB1TD/z2eeaINhLx+PLZNwIIGkiyrK80
	J2xtiAqCzMiZb7CdNNxgsNNDQ==
X-Received: by 2002:a2e:a98f:0:b0:333:9b93:357f with SMTP id
 38308e7fff4ca-3353078bda5mr5810661fa.38.1755603672094; Tue, 19 Aug 2025
 04:41:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
 <20250813133812.926145-7-ethan.w.s.graham@gmail.com> <CANpmjNMXnXf879XZc-skhbv17sjppwzr0VGYPrrWokCejfOT1A@mail.gmail.com>
 <CALrw=nFKv9ORN=w26UZB1qEi904DP1V5oqDsQv7mt8QGVhPW1A@mail.gmail.com>
 <20250815011744.GB1302@sol> <CALrw=nHcpDNwOV6ROGsXq8TtaPNGC4kGf_5YDTfVs2U1+wjRhg@mail.gmail.com>
 <CANpmjNOdq9iwuS9u6NhCrZ+AsM+_pAfZXZsTmpXMPacjRjV80g@mail.gmail.com>
In-Reply-To: <CANpmjNOdq9iwuS9u6NhCrZ+AsM+_pAfZXZsTmpXMPacjRjV80g@mail.gmail.com>
From: "'Ignat Korchagin' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Aug 2025 12:41:00 +0100
X-Gm-Features: Ac12FXy2y5KT1jl8o7nCrDwuS7gusbjmLZ1TSw-6nmPiK4uS84cdgeiBBwhyLx0
Message-ID: <CALrw=nGo5CfZseNwM88uqoTDwfmuD7BgXaijpCU-7qefx8+BZA@mail.gmail.com>
Subject: Re: [PATCH v1 RFC 6/6] crypto: implement KFuzzTest targets for PKCS7
 and RSA parsing
To: Marco Elver <elver@google.com>
Cc: Eric Biggers <ebiggers@kernel.org>, Ethan Graham <ethan.w.s.graham@gmail.com>, 
	ethangraham@google.com, glider@google.com, andreyknvl@gmail.com, 
	brendan.higgins@linux.dev, davidgow@google.com, dvyukov@google.com, 
	jannh@google.com, rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	David Howells <dhowells@redhat.com>, Lukas Wunner <lukas@wunner.de>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	"open list:HARDWARE RANDOM NUMBER GENERATOR CORE" <linux-crypto@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ignat@cloudflare.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cloudflare.com header.s=google09082023 header.b="A6nS/oc8";
       spf=pass (google.com: domain of ignat@cloudflare.com designates
 2a00:1450:4864:20::22e as permitted sender) smtp.mailfrom=ignat@cloudflare.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=cloudflare.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Ignat Korchagin <ignat@cloudflare.com>
Reply-To: Ignat Korchagin <ignat@cloudflare.com>
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

On Tue, Aug 19, 2025 at 11:08=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> On Fri, 15 Aug 2025 at 15:00, Ignat Korchagin <ignat@cloudflare.com> wrot=
e:
> >
> > On Fri, Aug 15, 2025 at 2:18=E2=80=AFAM Eric Biggers <ebiggers@kernel.o=
rg> wrote:
> > >
> > > On Thu, Aug 14, 2025 at 04:28:13PM +0100, Ignat Korchagin wrote:
> > > > Not sure if it has been mentioned elsewhere, but one thing I alread=
y
> > > > don't like about it is that these definitions "pollute" the actual
> > > > source files. Might not be such a big deal here, but kernel source
> > > > files for core subsystems tend to become quite large and complex
> > > > already, so not a great idea to make them even larger and harder to
> > > > follow with fuzz definitions.
> > > >
> > > > As far as I'm aware, for the same reason KUnit [1] is not that popu=
lar
> > > > (or at least less popular than other approaches, like selftests [2]=
).
> > > > Is it possible to make it that these definitions live in separate
> > > > files or even closer to selftests?
> > >
> > > That's not the impression I get.  KUnit suites are normally defined i=
n
> > > separate files, and KUnit seems to be increasing in popularity.
> >
> > Great! Either I was wrong from the start or it changed and I haven't
> > looked there recently.
> >
> > > KFuzzTest can use separate files too, it looks like?
> > >
> > > Would it make any sense for fuzz tests to be a special type of KUnit
> > > test, instead of a separate framework?
> >
> > I think so, if possible. There is always some hurdles adopting new
> > framework, but if it would be a new feature of an existing one (either
> > KUnit or selftests - whatever fits better semantically), the existing
> > users of that framework are more likely to pick it up.
>
> The dependency would be in name only (i.e. "branding"). Right now it's
> possible to use KFuzzTest without the KUnit dependency. So there is
> technical merit to decouple.

Probably strong (Kbuild) dependency is not what I was thinking about,
rather just semantical similarity. That is, if I "learned" KUnit -
KFuzzTest is easy to pick up for me.

> Would sufficient documentation, and perhaps suggesting separate files
> to be the canonical way of defining KFuzzTests, improve the situation?

Probably.

> For example something like:
> For subsystem foo.c, define a KFuzzTest in foo_kfuzz.c, and then in
> the Makfile add "obj-$(CONFIG_KFUZZTEST) +=3D foo_kfuzz.o".
> Alternatively, to test internal static functions, place the KFuzzTest
> harness in a file foo_kfuzz.h, and include at the bottom of foo.c.

Having includes at the bottom of the file feels weird and "leaks"
kfuzz tests into the sources. Perhaps we can somehow rely on the fact
that kernel is a flat address space and you can always get the address
of a symbol (even if static - similar to how eBPF kprobes do it)? Or
have a bit more complex Kbuild configuration: for example
"foo_kfuzz.c" would include "foo.c" (although including .c files also
feels weird). If CONFIG_KFUZZTEST is disabled, Kbuild just includes
"foo.o", if enabled we include "foo_kfuzz.o" (which includes foo.c as
a source).

Ignat

> Alex, Ethan, and KUnit folks: What's your preference?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALrw%3DnGo5CfZseNwM88uqoTDwfmuD7BgXaijpCU-7qefx8%2BBZA%40mail.gmail.com.
