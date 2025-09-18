Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBGX7WHDAMGQE32NAIRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F795B872F5
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 23:54:35 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45de5fdda1asf7852925e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 14:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758232475; cv=pass;
        d=google.com; s=arc-20240605;
        b=c0sBgopYcGnHWY6ZE8gNbCW1P5W5XrYBcxSWxifwLWz+gpDLXPDAzLnsn7VTsTTw5p
         +NRvCy6hCG2mI3s90rAgDyljS84ozqMF+G0Fe2ClRI38hMNUyYLOAZ9GxAdLXNVm0/3j
         /b95Yd7MpixSF2DsIpsPaioyDkqA9VegEWxODFJY/Vj8xEUq6ui8/mwjSb32IZM5NG2y
         sLIGmJO5BUti4+pbwhscOrXRbkLbFQYvBWwPXGYQ38GMN+u+M5D9FdVvg3aBVALqc6Ly
         RewMDSrQ1kVVJFrha7Q6ocBxshnlQvC6clmpvLDk6FXEtL/RvPdnI74N4NzKTjMYn8Fv
         a1YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bSWJwKtgzxbIn7dKRlmkhwS4gv0aJvY9Sb5A6dYFh84=;
        fh=9DzGbRS+/x+E7+IK6xbvvzNcyDeItx4XDsCWINWyW84=;
        b=W9a38+hH5niB7G+ojdC8we6Faw/VIcxtcBJ52BFKwl43+xJbnnsR07osrQWKPAczmJ
         kHDrcKU96BkmpJ4EWsDm9CdQqd6xVCWaJdmWNhpZjlDXoScTTPXDqlFzFTmvbRIgiILv
         Rgqkb12cG9CXcNFxfDiGIoNK1Z1DWtRuFh8UPOewPscVYJ59nd8Cx5xAOiEyMPo1dWtt
         HstDn3eUAQ5t2Q84JqE7ecuXYEhufhkUCsJMfml1SnVtDNBqLpJUR5h2a4l7DsIu7alL
         vu5LaapP/uTX3xVQBCX0qZF6cAU56A8mVc0UU9dT3oaDkgqEhW4Y/TuXI3N9Z4OFnVzo
         x4vQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=BnkrEcKu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758232475; x=1758837275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bSWJwKtgzxbIn7dKRlmkhwS4gv0aJvY9Sb5A6dYFh84=;
        b=mAbk4XQ4BhPC7TmSQ5X6sB8ihRownulgkcdqsjrP02GgYIWVwiKDZOCgyPJiV/a48T
         jqHr7hSNNKGqrrpbjQwG4u+MKY4LKjad159KOpNfCqO+/yezjCehpdPPJiIQ8cRH0xzg
         OxX0t2qxeHJKinfaRgoQUFgSibDBG0sd12EnCwlb+wSOeMsABQJ5M5048h+6ZDRxR5/b
         mTp1402BBXxKQdwg27sQgcpVkTUrfV45kKWyUhEvoTM2BdJoIaTkW+OyMCLvzoCxeQOn
         L+HKRer+Iie4rei1k+pk5j/L31wHZoR2t6jDoyEiwnF8tVlCsHpQK4rHw2vTarOwx0T/
         a12A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758232475; x=1758837275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bSWJwKtgzxbIn7dKRlmkhwS4gv0aJvY9Sb5A6dYFh84=;
        b=lAeDymqvkkvTDo2uKGy5wjkkEhTCoLSPJoYVc4GntHBrpaRUuUp/6VkGQcHQWX2mzb
         I7+2EeyjLsE7q+NPKWcqEeOwuP3YL5e9zAP4ORKhAh7Xq3+nkj6S1jFFsSURDdQCkwZU
         x6una5T99TnNnloF+Cm7BrCYr1uJ/Z16++Ma/pz7DIY7RvDelesr9lf7exA4Em+7HSt7
         DbuTOSgOF/1Iq4bpnU89iJtBSrNgCMcR3QdgnVZEqd0hApf/9TcQXYyfBOxo3/JCjD3I
         gT4fFHQ3isRst9exHf7ZTnhTBxFrhuYU4p92ZXozLww5Cv+y+dvKTvhSMTZz0bF0wI0Y
         hpBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeZejszY/b4cw29VMJZprEoCeZ3guUvc1LxAtbwdnmM8GFyPnqGUMC1XOOYEzOj3mIBkVBqg==@lfdr.de
X-Gm-Message-State: AOJu0Ywkj36enfvuGhYQjGrnEpTbAztaScZighdfepbEYLIx2XnxP8vd
	phpYuv5VvcEoIKbcaudWy632BkDtfJ/XKZccuopgvdEwU/xr0QaEGbDk
X-Google-Smtp-Source: AGHT+IFlhKZHcFriW4fjgEH13refgfx39X5EE91m1xOQILd8cJSxA+Hvc+vfa6CBvMNtr9/ZdCO/0w==
X-Received: by 2002:a05:600c:3587:b0:45b:80ff:58f7 with SMTP id 5b1f17b1804b1-467eb603b52mr5720605e9.36.1758232474686;
        Thu, 18 Sep 2025 14:54:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4oiZkioRGgoPB9/pt2IDIkegBz5dtMha16SSTdOgBqQg==
Received: by 2002:a05:600d:f:b0:468:2a1f:69bf with SMTP id 5b1f17b1804b1-4682a1f6bbals493305e9.1.-pod-prod-02-eu;
 Thu, 18 Sep 2025 14:54:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqjdfqObO8hyGDn3wXbotbwEg1wwzl8vtA8yqOLuLcdDkWsl7PHMnk55X1Vpoq3GNgpHCSJt5Jak4=@googlegroups.com
X-Received: by 2002:a05:6000:2404:b0:3ec:a76e:95d6 with SMTP id ffacd0b85a97d-3ee86b84662mr516864f8f.55.1758232471738;
        Thu, 18 Sep 2025 14:54:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758232471; cv=none;
        d=google.com; s=arc-20240605;
        b=IGxmLZQocRn/cnDqIkhXXHF7+tjY1qOt1MhTzDmFeztdS05OFFh6FUJGwv4sGuDUwZ
         zjbNAhF0E9RiQ5U9CmjMC4JZas/ZqTlzbG7e0gjpdBrhy2Ec0gwTYw9YzNL9nho8PR1c
         vw3E/yKV/3xghrT8F5zKXl3SmBdKMcnOOpwVgbPMp8tIYjZtWe8+/U40ftBRmn81ebTb
         v155TYc1MD0KW073bnP3RXGAOLC6vbxPLs+sPNpHQTtvAPHu4+fD6lyxlF13Z+l2Wmcx
         WLPsX1CzinLgxFbhkrDj5ZtoA/kmamo00tzG9bAqcCrrKWhbawkOF7H4kROGicaFH3r4
         OI1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mLiszfQw8YctXWgw7Rv1CzeIAYsEhv/enJDimwborHo=;
        fh=fwZC+cGua893f+6R/3u4mtf47DbDYK2jBNcJCS/0X6U=;
        b=MkEoLugKMXHwcVS9NrYVjARlk5TJtbAo97XTd1IxOhtO4f+FuEfvjC/uAKIY8cHS1S
         PoZ5lr3xMNwt1m7BrMxw8xtATcM+y4rDLRQCgGY/8jhJJLR6Vxn6BBnKZE3qy8iL9c0O
         55VmpsQUy1pmCUwajXz9KF8UrdXIXAPGoMvlDtOPeMnTB0Yv0fbBzOl1W3f4DzOr4K9m
         bfJR8dwoTfbkHS2iH48mGYyfEDrWUP26nm9ndASeY/zB7tqvRK45G3xlJTksyvgFBQ2b
         JoS2KhraCLQxZX8u4Ygo7U/0DNbUuU2YkUulEyYYGfE5I3xuudfJ7petULauODAW3+R0
         7O8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=BnkrEcKu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-464ef87c84fsi734835e9.1.2025.09.18.14.54.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 14:54:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-55f7039aa1eso1638574e87.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 14:54:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVHiT9NEQSnzcvxEMzSFxkCQxyVTfpQZ4sKhFibMhum8qy3hYg2UERoBaHpw+XMENS9YxWM9dJ3tEo=@googlegroups.com
X-Gm-Gg: ASbGncvCDxmxllvcmAxxZMjwLni5leaTjgf1oAFBcnFXIn9PaXg1eWIwebS9Y3wXdj1
	xyR04k0Uu63p1zoKStK35TKvGxHKCpQaYYetLZpIVP9Z967wOGF/rWDAQd9Ig33aEP4J5mMcPVV
	FCvn6XHVFnfs8jk/w1+Vg6q1rqdGczB8LCaizX7ctIyftfmT9NQeiK1stOYuUm3j7g0ccbxdd4s
	7flTW6mWircsXc2RmkSRD6TbYIe7wWITr5na59brtVh6GoL/6kdKliVbP3HHO+qsyMK6cx9TKcJ
	CDXOObFzePFIhm8ME8qlgGBerO82c6MO3g+dDkA1r9O3NS3umVl93G4fiIxhOfIhQjuVpJXiujw
	099BvfZrWv+gshN2+y5OLuYArM+l/aw9Crx11UxSoA/8STn7x0CDWCGXEQiK8B3Bd16wrI1vUVf
	h7YduHeTMVHvZmXUk=
X-Received: by 2002:a05:6512:158b:b0:55f:4bf6:efeb with SMTP id 2adb3069b0e04-579e28e08demr398927e87.43.1758232470723;
        Thu, 18 Sep 2025 14:54:30 -0700 (PDT)
Received: from mail-lf1-f44.google.com (mail-lf1-f44.google.com. [209.85.167.44])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-57946afcc2csm603965e87.38.2025.09.18.14.54.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 14:54:30 -0700 (PDT)
Received: by mail-lf1-f44.google.com with SMTP id 2adb3069b0e04-5607a240c75so1525417e87.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 14:54:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVEZz/takg81nuaVfQo1gQU7rqa+OVJ8MO5NX/5+Av5/l6apUGMzspqGSUgBANNjEnfI3S5fsxr2fI=@googlegroups.com
X-Received: by 2002:a17:906:dc89:b0:b0f:a22a:4c30 with SMTP id
 a640c23a62f3a-b24f5685fdemr62738866b.47.1758232077501; Thu, 18 Sep 2025
 14:47:57 -0700 (PDT)
MIME-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com> <CAHk-=wgd-Wcp0GpYaQnU7S9ci+FvFmaNw1gm75mzf0ZWdNLxvw@mail.gmail.com>
 <aMx4-B_WAtX2aiKx@elver.google.com>
In-Reply-To: <aMx4-B_WAtX2aiKx@elver.google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 18 Sep 2025 14:47:41 -0700
X-Gmail-Original-Message-ID: <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
X-Gm-Features: AS18NWBxHuMwwtU-EoNbPFA3uJ1YRJkAKqdurj12n-PWNJgH6ecKwZ8QZrX3P28
Message-ID: <CAHk-=wgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and Locking-Analysis
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
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
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=BnkrEcKu;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
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

On Thu, 18 Sept 2025 at 14:26, Marco Elver <elver@google.com> wrote:
>
> Fair points. "Context Analysis" makes sense, but it makes the thing
> (e.g. lock) used to establish that context a little awkward to refer to
> -- see half-baked attempt at reworking the documentation below.

Yeah, I agree that some of that reads more than a bit oddly.

I wonder if we could talk about "context analysis", but then when
discussing what is *held* for a particular context, call that a
"context token" or something like that?

But I don't mind your "Context guard" notion either. I'm not loving
it, but it's not offensive to me either.

Then the language would be feel fairly straightforward,

Eg:

> +Context analysis is a way to specify permissibility of operations to depend on
> +contexts being held (or not held).

That "contexts being held" sounds odd, but talking about "context
markers", or "context tokens" would seem natural.

An alternative would be to not talk about markers / tokens / guards at
all, but simply about a context being *active*.

IOW, instead of wording it like this:

> +The set of contexts that are actually held by a given thread at a given point
> +in program execution is a run-time concept.

that talks about "being held", you could just state it in the sense of
the "set of contexts being active", and that immediately reads fairly
naturally, doesn't it?

Because a context is a *state* you are in, it's not something you hold on to.

The tokens - or whatever - would be only some internal implementation
detail of how the compiler keeps track of which state is active, not
the conceptual idea itself.

So you name states, and you have functions to mark those context
states as being entered or exited, but you don't really even have to
talk about "holding" anything.

No?

               Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwgQO7c0zc8_VwaVSzG3fEVFFcjWzVBKM4jYjv8UiD2dkg%40mail.gmail.com.
