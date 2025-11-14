Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH623TEAMGQEDDJXBKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FBF5C5D514
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Nov 2025 14:22:42 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2958c80fcabsf50585055ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Nov 2025 05:22:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763126560; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y5mkupzGxAK4x0ErjoPFX+9A7yxDupHZ1RxkyJJ0LzcD+tiO0BSq+5VJByUaFRi4u1
         7CqKRquC1B6rHGFmvocoUK4qq2MEXdvgXWcvzLTD8AyFLXZjXRuS1svXnUq8PTC3EKj0
         S7jZk9/rsNygAkjcGLV58e2xstWFCb3DFeR0YfiWbQC5y+Q3/SesaBw2CTfwTiDoGNHj
         8VnoZQWxKoyG45r+/3H9wilPWVDYTSE0idAukSdwQriDDvGKE6gfQ+K0vGlTOEvPukfj
         pRBqOqGaiqn5OSkNOAAhVtBLj24gNoS1Z8mI7XtS5XvLwbmPDiVI8hA2u9pAcCGFlKwU
         Gmgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=22JL4McSYqGIKSSUUSVS8IHHmOeaT62r/4z4+hrwOnA=;
        fh=1MEUhyFeGjjHpdzEFfnveAYiRHVIG0dzBs+4DL0NCn8=;
        b=ge8ahuuNNiqSeuMnMt624oMMVSntqxoePQUAJFVNQFmGF0PwN7zSfGJ+ZowjPe8I+X
         0RT33YlR676dgPmij8il8HOmaxqpx7OcdO41ryWCrSN1gEvJ5aYdRnUth+c0W97Q1R8W
         s27+UrCCj0rjDuIlNXqf50MYukIC8oddWlHUGYtXxC9YnuJRSBkKT5Tkl6PJEi5gNSNE
         0Bo6bQ4bZENtMrae5z++wz/PLKfncMADOzjN2AA+6LngiCSvTrAw+9dWEIvJ0O+3Fs1p
         z8jH4OXXPiWrThpDwXmlBY/QNdcPvtPjUefPo9Gsbb20q+IiU9eMDZxjTwKqC/PVAYyL
         PeDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MLpQ2qvP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763126560; x=1763731360; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=22JL4McSYqGIKSSUUSVS8IHHmOeaT62r/4z4+hrwOnA=;
        b=kA1l4v401Y71HGq7TODLoLbcoSlzLx4Rm2vSdhi9Ccic/EkWFEyr6bRHF6k+53ME4e
         36nspVglmUKJTijfCBaRo63OKfsQqT7bpDYmgKoe5JkgzuJLazpMDkH+WBaju1YWSFPz
         iAMMTTV9so0qYRQVd4BDRI1xBoukpBrE2J9wcXdODwNcM4NLVw/WKwBuP3AmDGX42F+i
         IzKsDm+Tx/yQqOEHgt7dchvVkI3W6/RXE3bKpRUM0kSv0tYFII2OZlb7TcLigfge0DF4
         vNyo7w1WcDkcDzM5rvvC72j/tL3xxLLhuVtvvjedTqi91TEht2LmDvi7VNjjvc8INkom
         3+Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763126560; x=1763731360;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=22JL4McSYqGIKSSUUSVS8IHHmOeaT62r/4z4+hrwOnA=;
        b=SujU29iNbMVVd8+RmLlJ+a/C7t7/LJTSEbOKRY9+QJylrW6EQGMtfyMpvC28PFonQB
         c0bA+EvQsqTfcFOFfUO/24oQmXKT3R+o5YQfksrnfPEIPlE+Ru0vD5T2bl1P3R/JtE/1
         uYhIawRBNXV0GlXxzzC4eUpEkRVsflisdgQZJxc6RF4R5XUCzowhkUHgrcIHdU+VNqVm
         2Rh94lxj3g2T3eTEaGMybmSercbECDy77V07Vm2daDW3suS0C1J3GQv58Hd/HqKcapUb
         0vQCHobxJ4FiUmYR62IYaW1BbqlPd/qBHiRpOECCxs+K+gC22ZrKXLDuhPApGGBNd1k+
         cVRg==
X-Forwarded-Encrypted: i=2; AJvYcCVe7aMZvE0+c3A18M8hk4Bqq3LJ13uTN6Gltb0i2/CVDPZU8tMNXgBuc74K/i8mbJPQSn9z+A==@lfdr.de
X-Gm-Message-State: AOJu0YwcvwQMOFXUBXF5lU7i49XgZWMnFgCnRAbl/Uu23eSSyjhnkmIO
	sM2+cVwM9D499aSTttqwPuz8D9nmiF+98YCFaWHs/3juaPaZkJJO5tTH
X-Google-Smtp-Source: AGHT+IG1r9VqYMDvyUN09YjGT9D/kEeuopGuAFUBMwJ53z2jvUQKYb9HUn0iKZhkbYwZGcH2/szu+Q==
X-Received: by 2002:a17:902:cf08:b0:265:47:a7bd with SMTP id d9443c01a7336-2986a6bcff3mr35514135ad.4.1763126560459;
        Fri, 14 Nov 2025 05:22:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z4nNcHzZrgplpXTfUJ7RNqSF81EzGIi2L074ANw+i2ag=="
Received: by 2002:a17:902:d714:b0:267:fa7d:b636 with SMTP id
 d9443c01a7336-2985ab1c10cls22748645ad.2.-pod-prod-03-us; Fri, 14 Nov 2025
 05:22:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFdhhF/RQBJ7pZKPJ48snEr8Oj7rgPoiohKZ87cog0vM+/U+2G0WgKK2Sjlq9MtiXJeoCDUqfB+5w=@googlegroups.com
X-Received: by 2002:a17:903:234a:b0:294:f310:5218 with SMTP id d9443c01a7336-2986a600ba7mr29931775ad.0.1763126558671;
        Fri, 14 Nov 2025 05:22:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763126558; cv=none;
        d=google.com; s=arc-20240605;
        b=PjS2QCHDkrdK+xtC+UHvMdo4E5ScUeZN2sFRXVGljx/0tXncw0kjMl3UsfgYNnbu6Q
         +QIYqlJRoUN7DL8M8fGSOx5UKGXGh8MFTd92wBKmd78YNq6LglU64bOLW+m8XPwwCPBF
         gnKoQ95tMcSCevUq0NrXXR2mHlmNjgk0tvlmn1CcMUuBYx9r8S0tAbHkLoRxiPln18vB
         lh0S5/xJKgyOBpr/vJa3PKbiquhHcd33hlM/vWtD2jGK4SEs15p13StL1eTB2HVf1t3U
         NY3Wyha22UMGBGXylAM97n7tLWQpYe/rTrVqDbsEh6K0QmNxvzqjUtuu06Wf0BGOUHc/
         BN0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FuZEuvQ3jmbwZpx7rFiCevGNtHp2p1kTZ05rKerm0EM=;
        fh=v92fyqQNcWnBakV0nJGWZFAow4VvoGketkL/EF6pKmw=;
        b=JF0U9a7fVTNX4QxvNKHtwOP3NZPflHg0nU6BpHSIESVzbPjF0U8P7wjC3TdKM1B4ro
         CGBb5jaljrhPr024Nc8fb1OgEw+8+FyEHCHtrnFe97F6WCq2As6/9m2qVeGJRx+jKEQ/
         6bRV5AffL/pFiE5hDBFsnu47m7WaHAOmGTolnR84rEoY6W938bD4XJCGBjpVD7X+6Pyn
         DBV9Fl13egG/Dauea3SMpsLHATtaZtZ4oruSs5Yf2T9US9FfeD8QPGN0AAbZ9gq0PDtB
         VBolU97JUGavB9ReqAaNkp9p+eZQej4HK2wxJGAl3VrT0WpbVZPqe9K0Tt9MJSIULMtL
         HNBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MLpQ2qvP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2985c27e49bsi3080975ad.4.2025.11.14.05.22.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Nov 2025 05:22:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-3436d6ca17bso2118078a91.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Nov 2025 05:22:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUJTWsoFq9KLOs9m2T30z+yR28sILY1H37j8GikXIU/WsHijQx/vxNffOHTI02dKZj0xGUfLJdG/y8=@googlegroups.com
X-Gm-Gg: ASbGncutlJdhhxIYA8TM0czYphQJs1QadnbCqfVbMOSwv6+jajlvwFrlV9vFILLVH3u
	IWNlmuydSsP5ExsQp6ldAZjebIl7C3E1P9rLpYzUEeXMGQmUbxOZ7D0e16OVn1fQB+wsgYYQzRQ
	x+juLgeg0k3Rx0FWyMFSqmXvShsgKtHHJXH/ZCEPvIKNwaXqObzWKFvN8Y4EY4VD5rYaxeZtMGe
	BUD3tY4p7CNMoqYvV3ebaRUAyWlWmtkuk3LLxwlHvfb5tty743XJerLHrYJIPBOAHxA91A4YezP
	f4BcAPZQuwbKOLC75q0j5KYK6AlsvV7+ZZDT
X-Received: by 2002:a05:7022:6288:b0:119:e56c:189d with SMTP id
 a92af1059eb24-11b40f9ed09mr1186107c88.5.1763126557688; Fri, 14 Nov 2025
 05:22:37 -0800 (PST)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
 <aMx4-B_WAtX2aiKx@elver.google.com> <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
 <aM0eAk12fWsr9ZnV@elver.google.com> <CANpmjNNoKiFEW2VfGM7rdak7O8__U3S+Esub9yM=9Tq=02d_ag@mail.gmail.com>
 <20251114043812.GC2566209@ax162>
In-Reply-To: <20251114043812.GC2566209@ax162>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 14 Nov 2025 14:22:01 +0100
X-Gm-Features: AWmQ_blyYEkItbzeXoq8SnAQp2jhwPLGdi6tZz7V3PtwgmJC3W4HiUeTEvac_zI
Message-ID: <CANpmjNPniOK9K6q2sx7KRrxckeAdCyVnTi4qwLqoFoYzYb7L2Q@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Nathan Chancellor <nathan@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MLpQ2qvP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 14 Nov 2025 at 05:38, Nathan Chancellor <nathan@kernel.org> wrote:
> On Thu, Nov 13, 2025 at 03:30:08PM +0100, Marco Elver wrote:
> > On Fri, 19 Sept 2025 at 11:10, Marco Elver <elver@google.com> wrote:
> > [..]
> > > I went with "context guard" to refer to the objects themselves, as that
> > > doesn't look too odd. It does match the concept of "guard" in
> > > <linux/cleanup.h>.
> > >
> > > See second attempt below.
> > [..]
> >
> > I finally got around baking this into a renamed series, that now calls
> > it "Context Analysis" - here's a preview:
> > https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log/?h=ctx-analysis/dev
> >
> > As for when we should give this v4 another try: I'm 50/50 on sending
> > this now vs. waiting for final Clang 22 to be released (~March 2026).
> >
> > Preferences?
>
> For the record, I can continue to upload clang snapshots for testing and
> validating this plus the sooner this hits a tree that goes into -next,
> the sooner the ClangBuiltLinux infrastructure can start testing it. I
> assume there will not need to be many compiler side fixes but if

I hope so ... Famous last words. ;-)

> __counted_by has shown us anything, it is that getting this stuff
> deployed and into the hands of people who want to use it is the only
> real way to find corner cases to address. No strong objection from me if
> you want to wait for clang-22 to actually be released though for more
> access.

Thanks, Nathan - having ClangBuiltLinux infra help test would be very helpful.
Unless I hear otherwise, I can send v4 next week for review - in case
of a v5 I will wait until ~March (as that coincides with Clang 22
release, and for lack of time on my end between Jan and March).
Could also skip the subsystem-enablement patches for now; only the
patches until the MAINTAINERS patch are the bare minimum, the rest can
be taken later by individual maintainers.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPniOK9K6q2sx7KRrxckeAdCyVnTi4qwLqoFoYzYb7L2Q%40mail.gmail.com.
