Return-Path: <kasan-dev+bncBCG5FM426MMRBQV6Z63QMGQEPOBCTRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 533639856CA
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 12:00:36 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-37cc4f28e88sf301716f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 03:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727258436; cv=pass;
        d=google.com; s=arc-20240605;
        b=HlF1nDMB6kU4QQ3u8E6y4Ifse7rmUeEiU3/R3I0y2BfETnNyC3/7K4XWy45xJI7ruv
         iNeCVkUzYaDvt/bOPOH3X4BK8DgAgTh6hvXqhFejjkiPM1cV6mkoWI1yJ2fa9yuX1rlQ
         fV8YntM6vsGqLKlUUYXiRAI9TeBnU1vP20Qz8X74KsiqHzbM4+fXfHOxxRs+7bC3aKsW
         mCwXxkNFmtifiSsXtYom16dYOBxxQdLR/y9/p0hSnJrVRW59x61AV/MB8+Rr76bw2l5q
         1msAWgLt8PwoKq/nziSSHKZ2+O/G6HdPwYjgSLCRS9t1YtqWUvXcmVmYj9PRF+OchtZF
         5DZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6VnY77UHRYPJvNe9kc0/yd6BA5Ton1fnaUqVCBe1mW0=;
        fh=02Z8KWoN5pXi/b5wTpr6OO75CGC21qZii0oySDP+k2M=;
        b=eDuaZY1xFCne7q87+4rwwc/HERE+Kp2it/OKuj67+PT40Zmz2+FSMD78JBz+RUKLoW
         aP39Q7CP27urAZQacJvv67hHb2maIzXVJro85ikd3FS9J4FUS2ZBRMU+eT8woQu8+g8T
         6mbrmov/XZFABSvbu1/NYr6kaW+5THoZ3etNoAMwbAZ4GxqDpK+FMo/vyg2raEwFGpXi
         mHfp60aZhTAhIc1t4RHtQqLdmcmtjw8xNpZMbk4cKMxTWmvqGAdq0uH0sqEfFNy/6wF+
         uol85XG9K5slhiA3nZwgkSraDX+mWTWJ8LqZdFTg3yOSiF7WnUed99/LvP5p2HUzb60K
         /+pQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P5q2cdJM;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727258436; x=1727863236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6VnY77UHRYPJvNe9kc0/yd6BA5Ton1fnaUqVCBe1mW0=;
        b=FpzxzpCTfvMX7F1y4NVo0eE8HW2/fU9qqhG9e9rZueRR49cPDqdqnoYs0wl8iTn4hv
         yN0lUvORBUjoapNqhLrL5+JR8Ybx0BjmWp8OCv8/Ss5gz7Qf0bYqGnIIrG+3megCshkP
         tUWEjGtdLe8nuQjYLfxPB4kk3dbTwI7AuGQxMB6GYJ0WsWPhChWnA5Nu8eBraA3dDKcl
         dIr4M1T2BCgmtfPPYe0LMHFMCcnCdbL3+mkMqQ4z/JTSF0mnB1KNnc4k9fIEkUKXwtdu
         FaN5K+TMh330and+zEaBQ4jsxmSz+WJ3cU3aPj1a3wJoL6bOMhg9s0reDddTY6e6FL6X
         a4OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727258436; x=1727863236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6VnY77UHRYPJvNe9kc0/yd6BA5Ton1fnaUqVCBe1mW0=;
        b=JnlgnIDfyS/dmviOL0ey1aRjbUvqs11lqY7RCZFrIMZbt44bbr2RpM5Xf89/A94XWa
         SI+gqnAsx7Ol9gaEoEU7gq6F16c7AyejxTe7KTZcBF6OsQXHJsH+sYMQmJK1HZF0cxZy
         6xyCJCK1vFMn/xgL9xUibLyhwoWknE4SSZhb0bL5g4r8YkPKlm0S4zJp2xUGIZGtM5K3
         hpZxAG6QS4pGBBIop2/PaGC9vOl5SWW4gv3NDES4msvS81aOq1X01YepAM+VxNoYaWrV
         8ZBOSVgNNa3reqfMWTBA5NMUe8n3nJw9JhJWgRO6ha0D2sB7DgVbyHTcSKRWDQjjcAxg
         ousA==
X-Forwarded-Encrypted: i=2; AJvYcCXnCUL6KytLPdivm0g4cruMIAL+E64xOxN+RlmwzNoZBqLzaCpvM9MdPou3XH9JMFNkxYmkEg==@lfdr.de
X-Gm-Message-State: AOJu0YxbFzxIGbnQydvH8cC5QBuKp28kXpA8RBA4EBmzjAWZd3tXIzso
	1vShT7IENF5zJ+6TEUNDxKMHVaxeY8XBehvoEJ6mWTqP917xwP+z
X-Google-Smtp-Source: AGHT+IE4yUvM7jHtEaZIiVmoV9AKiIEsj0t2ixjGfSflqPV4wyapWHr5qlzon1HAJt8QuM9/zJZJxA==
X-Received: by 2002:a5d:5e0c:0:b0:37c:c5d6:e74 with SMTP id ffacd0b85a97d-37cc5d60ee2mr848086f8f.18.1727258434930;
        Wed, 25 Sep 2024 03:00:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b10:b0:42c:af42:6407 with SMTP id
 5b1f17b1804b1-42f50dbc6f6ls531865e9.0.-pod-prod-05-eu; Wed, 25 Sep 2024
 03:00:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrVKiCMkX3XipfPKmWbA3jHDax5SRwG/1vOC6Nr1Rk8BrqzvYpA9ecIkZLqF7Jb6rzBeXALo9kfBI=@googlegroups.com
X-Received: by 2002:a05:600c:1c82:b0:42c:ba83:3f00 with SMTP id 5b1f17b1804b1-42e961022a4mr18094215e9.1.1727258433101;
        Wed, 25 Sep 2024 03:00:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727258433; cv=none;
        d=google.com; s=arc-20240605;
        b=R57U3Mn88kOuxJUB5uINu2aTpCN3ELxPngS5Pg2N6gmqupQ9dzdyATJBjQZ+GhNAqB
         lM1F+plwB6n4otz3NllIkxPlHXTaP33YlTYgSAQERyq3QSyUn9nP6qJuKSarGwoY/Ct2
         HdMiDGixMYecDSQtLl1V6XkCzWPVczeFHWU22fMEmaX4glzJ6ymTYqjDOvdIzkKEFfcw
         Dm74A05KuG6NaGW2jMjCoHmVccQoKJ4RIA8bBRL1YAD4Zq2a24JQU4gSdf8Qguw7/CH0
         crMc0RZOFr2rYNvm1v8m9+0MsAYzhGpmwzCl7Mq7xqRf10eWI4fOqOow28+5Xaf8Yvcr
         baMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pzoOml1YCYEgfJn8QSXq3DVawdpDp//KSF0cYbIea6E=;
        fh=6lyj7gIy9Xz/tabqqQYwkPQFneNdOx6TQUqUPEJ3kXc=;
        b=l0Z3nN2rlFUmJHLoAFocPBYWblY0reqxvf8c0ldYGtFhwnj1GreJc6fCgQvszQ3eVZ
         X1shMe31PqnMr7WCZz2FGLy3mUkC5ArXrmuEh2hhQWimycpDzT6S+NcGkm7NDyqStkyT
         sjrmbSaivZkuPRBty4lr4L9FKN5jpFhOzjkRBNM89ZQYCiXuieXdI49YE71JI6lERvBG
         V7v+cK8SfPYPqqnqCHSUCuMTupiRfTERxB5Cv0koUY7svK1E0vyq7JJWrC5UbmH7oijs
         wLXhMEwdN9GzZ41FzBAAkwJu8kgP+jOIkHTgdjF1li482H45n3QpYJfu6gLvtQiGb3xD
         QVKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P5q2cdJM;
       spf=pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=aliceryhl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42e9025c970si2831505e9.0.2024.09.25.03.00.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 03:00:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-374ba74e9b6so5385381f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 03:00:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhnphPhlwd5uVbCOyYu+Qc25zK9zX7ddifkbNhYWfRT6bbQEb3BI70JV6rliHcCRax6i9nQLaEg+E=@googlegroups.com
X-Received: by 2002:a5d:5547:0:b0:371:8dd3:27c8 with SMTP id
 ffacd0b85a97d-37cc246a5cemr1937135f8f.23.1727258432326; Wed, 25 Sep 2024
 03:00:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240820194910.187826-1-mmaurer@google.com> <CANiq72mv5E0PvZRW5eAEvqvqj74PH01hcRhLWTouB4z32jTeSA@mail.gmail.com>
 <CANiq72myZL4_poCMuNFevtpYYc0V0embjSuKb7y=C+m3vVA_8g@mail.gmail.com> <CAH5fLgheG47LdgJGX6grHXL6h08tsSM1DACRkkzQk_1U8VAOxQ@mail.gmail.com>
In-Reply-To: <CAH5fLgheG47LdgJGX6grHXL6h08tsSM1DACRkkzQk_1U8VAOxQ@mail.gmail.com>
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Sep 2024 12:00:19 +0200
Message-ID: <CAH5fLgj7E03DKBcptgmZ8SLgco=Qs4puO=O6=v9=-3SSuqJyUQ@mail.gmail.com>
Subject: Re: [PATCH v4 0/4] Rust KASAN Support
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Matthew Maurer <mmaurer@google.com>, andreyknvl@gmail.com, ojeda@kernel.org, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, dvyukov@google.com, samitolvanen@google.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, glider@google.com, 
	ryabinin.a.a@gmail.com, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	=?UTF-8?Q?Bj=C3=B6rn_Roy_Baron?= <bjorn3_gh@protonmail.com>, 
	Benno Lossin <benno.lossin@proton.me>, Andreas Hindborg <a.hindborg@samsung.com>, 
	Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, rust-for-linux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=P5q2cdJM;       spf=pass
 (google.com: domain of aliceryhl@google.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=aliceryhl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

On Wed, Sep 25, 2024 at 10:26=E2=80=AFAM Alice Ryhl <aliceryhl@google.com> =
wrote:
>
> On Mon, Sep 16, 2024 at 6:47=E2=80=AFPM Miguel Ojeda
> <miguel.ojeda.sandonis@gmail.com> wrote:
> >
> > On Mon, Sep 16, 2024 at 6:15=E2=80=AFPM Miguel Ojeda
> > <miguel.ojeda.sandonis@gmail.com> wrote:
> > >
> > > Applied to `rust-next` -- thanks everyone!
> >
> > Also, for KASAN + RETHUNK builds, I noticed objtool detects this:
> >
> >     samples/rust/rust_print.o: warning: objtool:
> > asan.module_ctor+0x17: 'naked' return found in MITIGATION_RETHUNK
> > build
> >     samples/rust/rust_print.o: warning: objtool:
> > asan.module_dtor+0x17: 'naked' return found in MITIGATION_RETHUNK
> > build
> >
> > And indeed from a quick look the `ret` is there.
> >
> > Since KASAN support is important, I decided to take it nevertheless,
> > but please let's make sure this is fixed during the cycle (or add a
> > "depends on").
>
> I figured out what the problem is. I will follow up with a fix soon.

I posted a fix:
https://github.com/rust-lang/rust/pull/130824

We'll need a check on RUSTC_VERSION in Kconfig for this. If the PR
gets merged within the next 22 days, this will land in 1.83.0. Would
you like me to send a fix with that version number now or wait for it
to get merged before I send that fix?

Alice

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAH5fLgj7E03DKBcptgmZ8SLgco%3DQs4puO%3DO6%3Dv9%3D-3SSuqJyUQ%40mai=
l.gmail.com.
