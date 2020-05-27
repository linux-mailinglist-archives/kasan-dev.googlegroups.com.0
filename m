Return-Path: <kasan-dev+bncBDEKVJM7XAHRBDU5XH3AKGQEJIFPYPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 68BA31E3FF9
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 13:27:10 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id f17sf8765420ejc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 04:27:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590578830; cv=pass;
        d=google.com; s=arc-20160816;
        b=YVMpvbh++doQGi2a5O8pB/2hZ8hwp6SOzFFTOyY1tuDdykUTHO5m+w6m6Q1+l2+Dxf
         MEJ4Qha+DikPNI+xuPBAyv3F6q9JdBDBDct1nIGwxnyVoLre0IE5m6lzKlXrVmHt/Zd8
         G6ENAH3RSHufZyInWZG/B1aTTI/S9IoYppgyNvmabNWh2iI8cB4EnudmGjISCSxNhh3P
         CI8EA235uEZEalMepEHxwYu4skzj5WHkDUPthvigzz9CDS6SE+lwAebidCmPdeFWHnhU
         LGEBt5BRwrJSZj/1iXJC+zgVOQ7ZbewueHJiTWBiEoe9jUHSfBzu9SAA1EKGtROCNIEA
         UioA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=z5TPLOPN0pzxQqSlC6J81QJ8dwUHAZM8AeaxF0UxXGU=;
        b=lLIZUXcYUUm5Dc4Ihk7bCTWbCxPMZsPQ3DkuiXRlEF4Rlr0ev/6ie4Kxb5XOKhn6y7
         B5oBR9eUCP6Ci8G2oUm9HfRdy79G3ixEF+B7HUVx5MMx07kmR1on37zucVgCwLSJ6wiq
         QMOHARG9IcXig/ZQs+RRvTgduF9cuZQJ+oM+fdWjjTZJZE5jdKaBmGx54hSA1ChS2PNI
         XROiiduhQO+o+i1DD7SUaAMbAtmjviC/7khrmzwvXN6L9+yxlD3iXUI3x4rJcgQWsPT9
         KioqTcBJZsGxDIPlDpzkXoaSm+gFNNtHu/1mA+y8fbfFJTGnJTY5HMLLU0QH6exto+lG
         tTng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.75 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z5TPLOPN0pzxQqSlC6J81QJ8dwUHAZM8AeaxF0UxXGU=;
        b=DnHuPLvwTp2QOnicUVavdNmFntFyKxy/OzxLZM+R3W6FLWcJ5Gg9Z3Cm+XEijAnyWw
         Xc/5tsF6gV7cCULvJfzNgyWgvuoy4NLzvrCXOkKs9nDjXnxjeMMkgMk+aWJM5vGL4TMM
         iii1U+lAc8W3dCkYaNYsXEAQwqp8uEGqBdu28flDJFGY5bXMAtUG5tJ+s6L+pSEejzbL
         qsN1L23ryarL8WVdPKUX4FU246zH3xPPUW2BaoeZp57py5Afr7NAvIR5mlHfFyvu7LLc
         wOc/wCeG4EtiAbTQjURmIlIYJXmPAcMU4lnHiAXOE3nieyDlaaDBvPyNihJFbYZ7mcZD
         pLTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z5TPLOPN0pzxQqSlC6J81QJ8dwUHAZM8AeaxF0UxXGU=;
        b=BNNxzXlVl5HYic5Gz0Cbx39PCKJ7Zvw7uJN/Wzl0+68rYqVbmCiyqQv3cXX5KxI2cU
         oOjnGyLUB33P1tBkoPFGW6+cGqvoVYsKtJcGzLl/YBGznwsfyTCOGmAyPdAfjejHy6/H
         FA+hBWeQmtuZId+9kCIJ7iZRuFfsqwUYMVfTlLuNY4j/ZALz5PjU+8zak683WHAkJzac
         9ykS/PvqlHetQFLRd7bGYBf6Z/ooj+RyMVv0AUbYJwPMl+6KldpXykQEerEqoUFIwB74
         /16vmzSW2Dhk8Ti61vUh1+EyQ1n9kT41zISbfDeTZ5FAfA6qASNBL5gbPJ5a8r6zkNoH
         Km8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532y5X4pktXlZHsO/ZPzcAAP/zpMaljOU8ETHgmkfqXh7dAcS49x
	C9xkqjlWLt8m9DvO91BSDOQ=
X-Google-Smtp-Source: ABdhPJy6LdXzxBM4TUlGy4WunpBdpKkOsrPeQtaoi1Mf1p0eDnrSlJcYLrjz0bsIP5Qc6FKs42a47w==
X-Received: by 2002:aa7:d71a:: with SMTP id t26mr18612318edq.123.1590578830130;
        Wed, 27 May 2020 04:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f21:: with SMTP id b30ls14772136edf.1.gmail; Wed, 27
 May 2020 04:27:09 -0700 (PDT)
X-Received: by 2002:a05:6402:1847:: with SMTP id v7mr15719819edy.73.1590578829584;
        Wed, 27 May 2020 04:27:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590578829; cv=none;
        d=google.com; s=arc-20160816;
        b=CoApHMOWQD99dUBcBwtFnVFSxktrTncIlVibjWKcISsy1R5R5fNZDD5oRiS3dUoEHT
         ZOFuGrZZT71vKE1votjp895TrAMwUA8zRGc/+X2mNpBJSSqubONVzCnOkfKl+QfbNxNo
         f5orZVdr/w1cUypF5AjUsM8ZgauK5jGJEv4H8F5326U9+kVYP8i3OKY0K0jB0Mr5vifM
         eA01dqX/Wr7It58yUjlCrFZackd0DEbzWGa8KWJxh7wVIu1wofP4nmK6s0t7oBHMrPIF
         QNZ/1myPB2T+OjFVdcGD9cEwRFqwC1ZXbk9acKV9+13n8mRaF+wWMJ3QmbfJ37VBRIHQ
         vVpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=uawALYrHZFhHKBQzwvHiRgX4LtFZuMYOk/gpUBYfqmA=;
        b=X9eYF8m7Iz2HB1HvYWdTxbKEZtSVJoD26a17RBDXE3wzs9U7gmwRmqmyReHhQv1zY0
         rctwnJzmvrBi2JK69FHJIvCLdWIWwqj3rAs7oMNR4CbdvEI8goPmjUyuJRskIOxrOQ1F
         +nmT46t/IoKR/b8NOhZRbIX3eXfd6n48QsP2hzuLZdTa3gFoSLNhpxCYFufdlHuG2WeV
         Q7EN/cXnVFV85G51+/2WB201/J8uAOgEAinkHak+I9/4hX60ZWxEY3a/9inaT6njgxId
         Mk/XwvS49d9hYANuIcgl7u3plDPH+YTo4DSFIX7Yy4fdW4gj1Bj1+DoRC1P8doSDOple
         SNJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.75 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.75])
        by gmr-mx.google.com with ESMTPS id m17si24153eda.1.2020.05.27.04.27.09
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 May 2020 04:27:09 -0700 (PDT)
Received-SPF: neutral (google.com: 217.72.192.75 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.75;
Received: from mail-qk1-f178.google.com ([209.85.222.178]) by
 mrelayeu.kundenserver.de (mreue108 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1Md6ZB-1j4ZKR3aKp-00aCuR; Wed, 27 May 2020 13:27:09 +0200
Received: by mail-qk1-f178.google.com with SMTP id v79so13841800qkb.10;
        Wed, 27 May 2020 04:27:08 -0700 (PDT)
X-Received: by 2002:a37:434b:: with SMTP id q72mr3711430qka.352.1590578827661;
 Wed, 27 May 2020 04:27:07 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com>
In-Reply-To: <20200527103236.148700-1-elver@google.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 27 May 2020 13:26:51 +0200
X-Gmail-Original-Message-ID: <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
Message-ID: <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:iq8ozJw+B/1XbYH6bu5K61HPoysgi5JTChHl+L/Oxf3r331WJxL
 aMmXps3ul4zpiYdfMKTPYMotNNgvIwFSV/KNQWLRgnVWlgbf/NJVkqmFbk++wke4JGQClJW
 wAoW3kihiD7pOBWc9Kr7I5HwRKpwOWDpFqdPpVyigKbHhLhpM4mKcR1ssJF6Ar7Sw0oQnt/
 Eowsxy3ZbmGKs6HcHop5Q==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:/Ewnb2SGfC0=:gZCi+xKkLsA2mNW1gkE6pU
 Rm22CJoTvmSVJJi7jqBplUFRehKCz3Hxyyad1sIpI/R9tQsQMhx3rC0SX98gXKnJFG+85MQfk
 Y//9nwz5ZRpVJg3x6xiE1JkWl90aps0Q1EPzr0HrBcf2eFIv/mJH7mMPY6TKE8Oro9oRq83jJ
 jli8VkoFi3Ja9kp+Te2TgX0GGZW6LnarT50TEt9ZI9sjP5Xvjm+cLuaIc1VAo8WRsDAGWtXvt
 5H59HeStCbyWIN0aNQpKJ7uzdTbCo0DC5Ac8nA+XR95nnb23Wa9225DGbgewZmgNpeXZb69PE
 WLbSFBTTomrSmRP2H593eSvW9shFgR69gznXOCjyakEOtKmMxDLNXSc2qp5Mvu4gPzpQA0oc9
 p3Fc/70XMbmbP4Oetl7r05vFcsNPG+xJT0vonA39y9F/8N6INAqmZIoZohoXo721rV4GA63nI
 vaOAFqQdLS9m+jIj4hLspUpUZkhfQBfKB67ShZGDe4j9FVJQfBQQOfxRy59TXcxVtu3eTLQM3
 UkmN7GFydUAbgLk2cy8gAMNng/WQKNXVwlEhc+NZWFCQ35iSw7M+Sdym8/J0X2moP59+puTZ8
 HI4MDGn/PFFfOhXhNeLiIyImmupo3cyAm4iIKFwBTTaBSyh2m+ZV64jTX/mIfRv2OSGmR6Bba
 lUF7bgtCSieibe1VMXhVyGEyJIsNHReXXi+UtOLgT9h9m/GFM+BAymeFVu+M6ezYf2+EVYsP6
 s8rX6sX/y7MXZO9hapKxuQSQZxPFIWHbtzyFfCWuIpVRcElQ6QRjPrJtGzfI5k+w5D39/O3G3
 CD/flpbLNqCYyHT96vUAEGsKXGG8FgKdtMH9SaYv0Qu+c33pX8=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.75 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
>
> If the compiler supports C11's _Generic, use it to speed up compilation
> times of __unqual_scalar_typeof(). GCC version 4.9 or later and
> all supported versions of Clang support the feature (the oldest
> supported compiler that doesn't support _Generic is GCC 4.8, for which
> we use the slower alternative).
>
> The non-_Generic variant relies on multiple expansions of
> __pick_integer_type -> __pick_scalar_type -> __builtin_choose_expr,
> which increases pre-processed code size, and can cause compile times to
> increase in files with numerous expansions of READ_ONCE(), or other
> users of __unqual_scalar_typeof().
>
> Summary of compile-time benchmarking done by Arnd Bergmann [1]:
>
>         <baseline normalized time>  clang-11   gcc-9
>         this patch                      0.78    0.91
>         ideal                           0.76    0.86
>
> [1] https://lkml.kernel.org/r/CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com
>
> Further compile-testing done with:
>         gcc 4.8, 4.9, 5.5, 6.4, 7.5, 8.4;
>         clang 9, 10.
>
> Reported-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>

This gives us back 80% of the performance drop on clang, and 50%
of the drop I saw with gcc, compared to current mainline.

Tested-by: Arnd Bergmann <arnd@arndb.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1MFgRxm6%3D%2B9WZKNzN%2BNc5fhrDso6orSNQaaa-0yqygYA%40mail.gmail.com.
