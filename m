Return-Path: <kasan-dev+bncBDRZHGH43YJRBHFIRPBQMGQEVEWPGYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id F0B03AEE693
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 20:14:53 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4a6ef72a544sf61687661cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jun 2025 11:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751307292; cv=pass;
        d=google.com; s=arc-20240605;
        b=dUAFbkhbqOj3UGAB5M80rW39hCDDH3EN0SarD2g8FXiwOunXSFSjQD+Ou09yuq5LKF
         P49mxsk/6Y0ObMi5y60xhN9K+WN5muJv28ZgjM5NBbEMgB91hlo/y8BfU356rTgrYI7c
         TlolP+2dU2OFOiZQqirtvaLgbGfzkWlnlXw9e2gBTRZWbPlrrhYOhNCDKDPkXMhG1SFk
         BexNl+aYpmJ4M32mc3PynmSH8gdIC13Ug/5w6emDS/Z/qzA9UmPKfYMCYaH85gBUwXQy
         HZdRpu3JlTbu9ibxzhHOgIqPlmCbdfpbUKkCyGe1VytZbpGyucYuzE5zafa35MQzgneo
         Avmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jKc8kVk7AqNhf0URzKkY0CAA/rDdaW3i+QHMWa6bEV8=;
        fh=FwwrTtrHnUs+rULajF5lcFwaHeqfwQv2lvKBnzzNsgQ=;
        b=gPALgdFyESY4Zhin9W85baGrMpoL/zsX7WrVtnRBd7AyBmpKrisNaQUBliIbzr6sh1
         Xoqnbc2tEecI4Oyewm6cQl3zh7OYqG6+PKuOIvo/v8XTOOr5khFuA2MYjomdXgujQITO
         Bk0CR1uGqc7nJJns/SbaI4cMB3J57PAggQkJjJ002mc+mJShe68osjffsTz7nvEU92d8
         AimyeJM7Ps6zrH/JFAFleSDEevH/L40Ze61YIbQYEKJ18WiuXTqVGb72ST8PWVfAljC4
         JZzpeRsL1cBc86qTZjOwzmKzrYnqOv2jK94UmSGPtNZwhSM5pPwWE805iuV0Jw5ycbOV
         nrmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QPmD9v0F;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751307292; x=1751912092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jKc8kVk7AqNhf0URzKkY0CAA/rDdaW3i+QHMWa6bEV8=;
        b=C1TGAembjx32FJUykit2cWjemwcwxV4NkzXzG0ZERFaML4IJOSu2r+K3pvAeYwdaZd
         jKqdeBKC6CqZKApQBqKUQsggdTVtElN0HWCjGbs6+Z7dt9/I+AtNCfkEpErHDNADD48x
         gcCpKE3pgf4qoE08r5Skik6svdEB4TSfzZthgs3Ymb6BT8sdeJdl/YqgaRgwrc1EZr7S
         IfyFYeJJmWYZ2H1smNoLSMu1e8t9MOyZTxnd8t38sbRWmLytxVQDElmRFAro60gGJqxA
         0KaCmBpbJLb63ywXW4KSZ0jjQDNc1Qx22VGSRngCOoqvSU+EpNSl4zn35XpIfO//wnXC
         ruYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751307292; x=1751912092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jKc8kVk7AqNhf0URzKkY0CAA/rDdaW3i+QHMWa6bEV8=;
        b=dNAOskogWC03MD+2gKMUZ7j3hh/Ab/wgdky5cqnsSceORb0pqz9GlQi2PthHWBEMOV
         K6PhZ6V2bynBlp969IMUuoIsgwtc/W3h3TK+YlOpRa4N2jnGp7SYS1/TLeZkd4SEyraj
         N7yE4a5iDiLb7ltgt70b+zpa59cm11mUrqiwSC1fzqiu6Ran351eQzre1Q1HJaQRf4pe
         O9iAu6ZJhsky7guXtTE84w83W5G2XfmX0HUqa+zl/jKvBd+zCZx9vCB1e1Ev3j6YpJ9u
         xGQXmEW1FTvMCDG7q9T/CKkD8zqSLMXCQ6hZGWdfeDpJB24RR0rbLK/YL4U+1iHHzVRJ
         wRnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751307292; x=1751912092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jKc8kVk7AqNhf0URzKkY0CAA/rDdaW3i+QHMWa6bEV8=;
        b=Lv5g0jllP8GfQRJdUC7QCUBwR8xCsZEnvj0V4PtQe/PO9+6hHCUIkc7AqHhG8jz+Oq
         RTPAYp2QhB9JBJ9ZLt0gnleWVpHb12KW6bFFb8GSuKgfi9hHx8WtS1UrXdmf/NV+avGR
         l0HdLBfusnmGhs3UlMa6nM314OC3neNNquwHIShmBaznYJugDtmbxMK0IH1y/eUwfpZc
         4nruJ/8H1pC5aPuiSVst9LGgaALf85mCTENpOysU+zji0QmdqUg0qpPPAF+bvPaVondK
         6Z9UvsQfWgF5UVPWC1RoYtocfXUcPKDG9nunnNC0+dZiL4S9oLe4CXVVzN8gLE/rUDAO
         6OtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjZBLMXS7yZLHkwDBfBt7arEO8HP+LPrjns0CdzYm5r5A8tFaY4RGv+lV+mM4hfL0ly4F7HQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+JaL2AZ1DsTjE6zjDr9E+AO5oDtFSJtytpIkoTS4kOem87Ykg
	7NAAu8KygelbYAmTNgXKpJ2pv8b9yknD8dipVl2z4isHVhDqDtWRlZoM
X-Google-Smtp-Source: AGHT+IE6YCJKqnyiF6xZD+71VbZBImWiBCffRiWu7aLYyQ6D/kUEunsjxXfJ1BgbotF1WAuVMMAfPg==
X-Received: by 2002:a05:622a:1103:b0:4a5:a4e9:1330 with SMTP id d75a77b69052e-4a7fcbf9f35mr247243361cf.50.1751307292217;
        Mon, 30 Jun 2025 11:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdn+h3JVMY7s1MF8B6YCOAXGzMgeGEZN9TBkC54X+GNLQ==
Received: by 2002:a05:622a:591:b0:4a4:3182:79af with SMTP id
 d75a77b69052e-4a7f32443e3ls99305001cf.2.-pod-prod-07-us; Mon, 30 Jun 2025
 11:14:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo8HgeZM7B2tyyIQ8WneZdiP4FJuknOOLE4OUFHisyv6I+VBGiZWcoTqVPv12uxofKlRW6QwgiKhk=@googlegroups.com
X-Received: by 2002:a05:622a:548c:b0:4a4:2c75:aa57 with SMTP id d75a77b69052e-4a8074916camr176899411cf.44.1751307291180;
        Mon, 30 Jun 2025 11:14:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751307291; cv=none;
        d=google.com; s=arc-20240605;
        b=NO3kpwI21MKIOZY58M1DCvKyDLqRkRaAlJZz+e7aPnuZf8Ek++pVgysNFSSV9Z01cu
         R/PH8I2E02BU81A9wTW5HyvJCUxEfeSBCHAR5dH0Tbjv2RGUTKMwFkg/tH0baceh+qyE
         y//t05a2UO3weW+vGrvvNPftb07kjF54y/2SLXx/wBUYQraPyFiRH2nCIQ0ybVFE9jsG
         IydYWZwztjl2s/GFIL/7KAHfnget2gxzXsFrA5pxTd8RWMQGIBIFeJ0lLkyDYmghVFyK
         KR4sn7Ml1WOIECTN7O0JQapaNHFYQcp1Z4sXYz9Ql0TApR2qt6bflEYfSL8RPb2V1pZH
         4CQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fjh4vA0/9tGFd6ND+oD1KaKIqLUUdClc6Lc/84XmOxg=;
        fh=bNO9Ru+qREVMlnqcRRv/Z6w1CXI5/JseLXZOABh804U=;
        b=KFu1dcg4TwvBmc7pirf0+qtRszcjDVKfvPLP9csdocnpJCF3qjBNJZI+eoiPsJpDeo
         mkv5C0R9BJs5Wotj8D1mgzn+ATMJvxUNj3TZWXJEhlyvk4lgb5ZIeYYPbBHC7T9l8VKT
         UIFJqfxnqmGB+VNX5lgLgP1oZM4ZTA3K5M/ElNKMa22BPLvHaMiItCGjMSu3x352AHiY
         rWS6jLQWknhYDTEHGKDLLxrMduVqa7vjKV+kUxdetGtjQBE2dsH73+KDyr3OpHPCAbks
         kYszHyQoYfxBUZGL5FT4H8gQkFD7nkZLBVwmnJmPjDqboeMFanOb1tqW2QvWaxKw45gl
         3BTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QPmD9v0F;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a7fc190cacsi2253921cf.3.2025.06.30.11.14.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Jun 2025 11:14:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-313fab41fd5so1091600a91.1
        for <kasan-dev@googlegroups.com>; Mon, 30 Jun 2025 11:14:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZ3qkB8+jxyoy3FHSJ6U7G8Diz2n4hxXzYvqEJyLCIJOxS1NqD5EOpYHrx9zC5dvaD1iRcyV+apis=@googlegroups.com
X-Gm-Gg: ASbGncug69X+aNNXL3MIEWl/tn8JLDJ3fIPVhYa4fM4X8QQL6wzplNUUX9cFNLwy+xT
	xsaK8mknV+hDuAfx+S0eJ4lhvslJT3ZHAFaSYUT/2rqIZlepyGr/CLp8DoZmkQ0JORm0BAX00F+
	N3DidDqmsMr2q17HyFpHsfuRaBn3jIweAabtKHkeDw5Xk=
X-Received: by 2002:a17:90b:280a:b0:311:b0ec:135e with SMTP id
 98e67ed59e1d1-3195196fe9fmr128173a91.2.1751307290129; Mon, 30 Jun 2025
 11:14:50 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
 <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
 <CANiq72mEMS+fmR+J2WkzhDeOMR3c88TRdEEhP12r-WD3dHW7=w@mail.gmail.com> <20250630080910.GK1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250630080910.GK1613200@noisy.programming.kicks-ass.net>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 30 Jun 2025 20:14:37 +0200
X-Gm-Features: Ac12FXyb2DQrVYl-Dwvo78mZOTpBIY790W8DikLM5bA8rznRUGZ1aVN_EqjtnQw
Message-ID: <CANiq72nURu5usLAjj+C47iXPLRrJsNChWKGkVtw9MuDaHUzkfQ@mail.gmail.com>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
To: Peter Zijlstra <peterz@infradead.org>
Cc: Alexander Potapenko <glider@google.com>, Miguel Ojeda <ojeda@kernel.org>, quic_jiangenj@quicinc.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QPmD9v0F;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
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

On Mon, Jun 30, 2025 at 10:09=E2=80=AFAM Peter Zijlstra <peterz@infradead.o=
rg> wrote:
>
> Since clang format is an entirely optional thing, I don't think we
> should care about old versions when inconvenient. Perhaps stick to the
> very latest version.

I would love that, but I am not sure about others that use their
distribution toolchains (including for clang-format).

Hmm...

If it would now allow us to get very close to the average kernel
style, then we should definitely consider it -- years ago it wasn't
the case.

> You can have per directory .clang-format files to account for this. Eg.
> net/ can have its own file that allows their silly comment style etc.

Yeah, that is what I recommended in:

    https://docs.kernel.org/dev-tools/clang-format.html

But nobody actually added their own files so far. (Which I guess, in a
sense, is good... :)

> Still, in general I don't like linters, they're too rigid, its either
> all or nothing with those things.

There is `// clang-format off/on` to locally disable it, so that is an
escape hatch, but it is ugly, because we would still need to use it
too much with the current setup.

> And like I said, in my neovim-lsp adventures, I had to stomp hard on
> clang-format, it got in the way far more than it was helpful.

Yeah, clang-format for the kernel so far is most useful for getting
reasonable formatting on e.g. snippets of existing code in an IDE, and
possibly for new files where the maintainer is OK with the style (I
mention a bit of that in the docs above).

But we are not (or, at least, back then) at the point where we could
consider using it on existing files (e.g. just the alignment on
`#define`s makes it a mess in many cases).

I will take a look at the config later this cycle and see how we would
fare nowadays. It would be nice to get to the point where some
subsystems can just use it for new files and look good enough.

Thanks!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANiq72nURu5usLAjj%2BC47iXPLRrJsNChWKGkVtw9MuDaHUzkfQ%40mail.gmail.com.
