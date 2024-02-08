Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBCXOSKXAMGQEHFHCHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 055AA84DF7A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 12:12:12 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-51151b8de86sf1738956e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 03:12:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707390731; cv=pass;
        d=google.com; s=arc-20160816;
        b=hiEqfbjPpgQZJIsVMbsDPzhjMEktiJd0zxL+y8j8NBwTnghSdsuhd46Nr+NQ+gQca2
         90PqUOG9Op5P4rVD0Tw2AhIrqd6WysJt30dBC2YoOLCkJeRViMS+Zkp3wdU4GFqwZvlF
         qwjV25/1l9fbu3Tn+N/4V6hBO8eHn+AKZdldwBPE/MIe65nt3LDXZsAPV4WUQ4Y8NAhJ
         keB1H7Yk2fq2urXQP3+aJtdct63o49FihF0GEYGktSBwI5XxpmQS9nI3tkfefTxUXLjp
         qemDQETKf4OmWgo+ypecsmASemgOF/q4BwHRZ3NGPeoUV0n8LO5VUEQWIFPlUDZUe7ux
         dgtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HwmS7trLYdTLivrRloXxmWH1ESh8NXP8eA2r5HmJB/I=;
        fh=E6KhEa2+pShZ10R5tyt8h38B6HXDL0lCs9QvmizEKsc=;
        b=qGTYclBR66v+RTEcnV4xElKv2wlNRzIPsqtNpURxVo8A1CSFeC2q1dMA2KgYj/olS6
         hA/oiowYbVzj4MH/KACK0R3w+XO2TTd0//OfsWvi9PyciG8c+/qiVTdjjKESIOurKJwP
         ZCZ1WqJhQ0Orp5pn8jDVAyUd8wxZZosXtSvfhMAF5l+nVMTRL4sbVGzjQK9hwMD6mqaE
         P+VZFI7hVgSopW+h2V0IqRgGodm55kFqCfkUnJcjNlvd8S2iB8A4FuaTkEHc95pDYjW6
         wZ2c2h0Axj/wTkY9mZ4Ikn3amXHEvhyttObluB+6ooCJTPNwqHwsP5kYY4P/uGOGKZ+k
         2EdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Mo5id2g8;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707390731; x=1707995531; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HwmS7trLYdTLivrRloXxmWH1ESh8NXP8eA2r5HmJB/I=;
        b=GSua5sLbrOc4n4N5X0KzZgxK+m53rCkOERM71HTyit1Z6pv7+OAOGLGACJQI8lb5zX
         xMoHvFB+aVBe9/igTJcYTlShNX1k+ZvlRBvuKBhvPResdhrgj+oD99ZAW/uUyBhpx9YM
         WmkDZp4UevvdWY2uGn56ckNi79U7MgWLQdAFYicvHqp0o/Unpk5BiXaDBKh1m6ToylnV
         GPYAs7cuK8Be4DLfPFjatrMVGYqhvBz1BkOqgOE/UaBVSTzf//9EkOy3M4O0iHeEhVw/
         sgrbTDTqiOHXCrAdiJ2Jfl3AIHXaDpur8PIDbgKLOX90N07ssxLRzmQuPaFUjrtTRUM9
         vmaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707390731; x=1707995531;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HwmS7trLYdTLivrRloXxmWH1ESh8NXP8eA2r5HmJB/I=;
        b=ebRVszCuBwAa3PjW+chAnfKc/lVMa1vEFFUgBysiCIvqH+MNMF3LrLMHVSdmleoOmn
         O9zFXSFjWRkgG3EuvQW7Qcd6a5frglN/RHrHJS0Y48Gq6N3VSUYXtDj8UGJ34q5+49QY
         wvPeqiyJfmMLIaFzbHa9H0Kjs23IOFrACqX3iXLbVRPKjFuurd3V1sJfjdSNa0GbiI0r
         uU8I2PBWRnnmgz+eN0YNpfQHQZug3ZDwwQWPCWHhetXPxv5SXC0LJ4CYYzoAFHI7VdKL
         lRvGnnThlDJf+kM24SucxHWqthA3LdHEuU+haK37E3UdmzLGoSTMH3YcetJNiPlXefyG
         TTvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxDD4I0/gRJBScyWlH0mbqEscLAHUn2htWXbb064N4+fLZ7zmrQ
	TlDL1AwE8vKmA5wYTioHWtYQWHfBEMQwvAg5OV9HjIVyLYgKBMCP
X-Google-Smtp-Source: AGHT+IFLKK90epGHtp2G8fqXwcgxlmBfBVMqLdYu9VEIrthNJuA7ydeiNGxln8nUh9tiQ7RUHq2qxQ==
X-Received: by 2002:ac2:5b02:0:b0:511:51af:7548 with SMTP id v2-20020ac25b02000000b0051151af7548mr6022333lfn.9.1707390730596;
        Thu, 08 Feb 2024 03:12:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d06:b0:511:46e0:83c8 with SMTP id
 d6-20020a0565123d0600b0051146e083c8ls737503lfv.2.-pod-prod-07-eu; Thu, 08 Feb
 2024 03:12:08 -0800 (PST)
X-Received: by 2002:a2e:720b:0:b0:2d0:bc02:145f with SMTP id n11-20020a2e720b000000b002d0bc02145fmr5192039ljc.15.1707390728137;
        Thu, 08 Feb 2024 03:12:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707390728; cv=none;
        d=google.com; s=arc-20160816;
        b=EUSPhIh+RTM8mirLmpcpkSyd8GPtrAnVeBbUfhBszo+gLLj0tZ9Q3JYoFV9tZSE3Ri
         c3nDOl+IuBhNfkIQvD0BJOJf6MgBk9F0J5IxnVuDAEGpsDgH9IAtBvSkfPcysw8zc9w6
         juF62UEqV0G5oRorOfDYu9y+P2WuidjgaVFtYRXaaiiPUcrhZbX6JQ7cQ6O5i00QjHau
         qpGMDhAdbcql7GeIueoXmvRYmwsnFiC+2hnwgOAftABJ6fCnT/6YTQdPNGrgE4pXQTVW
         BWFQ5NoQGi2HS+jPXxd2TzLQcw6Uw0pUq9LnWuT69kP/74td+TKPgG1VV3mwrLveYYe/
         /lvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LaTp4U1LWb5pJxk+3p4oypsyvdSNZ1j6KLCLyUB+gDY=;
        fh=E6KhEa2+pShZ10R5tyt8h38B6HXDL0lCs9QvmizEKsc=;
        b=lKglm27L3FIJHT0rAbMVXK/GxGWrGMeWYuXmtYw582O85gim4/858tqNwIYgP7qPMx
         +MRjUsFU2fXK99FFSqhJ36c9NVYdnHd2a8XlsBw3SlRwEg7xuTB4IBV0+emeFR+Dmc/A
         +AyAkiHPYDpY2Ff1y4YJQklZ3JaDyiUXxTzDc435MeUwsADVLANK2DOZGHu2/Fr50zMv
         4J1xuiI5rdeZ1ksRJN2t0hq+8MW03hAC+MCbxlwBV00cxAdJBfq6GibwqQe6/67V07+f
         VXzB2G8q4YgUiSDoYWclMxhDHqBP1Rt5Uh72kZkBImQsidVycbde4towz7GN0seK4lhb
         NL3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=Mo5id2g8;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
X-Forwarded-Encrypted: i=1; AJvYcCUWT9gimuJ3XDQdq6MAlYyLmo/91I9CWN53OgvRs+CS8mEQ8bA+/2CxYS9BFKDkg3hWizcXPsjhZ7CD/rmf0rkYZsX0Y0qyIR3ccw==
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id s9-20020a2e81c9000000b002d0a7814671si246111ljg.7.2024.02.08.03.12.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Feb 2024 03:12:07 -0800 (PST)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id a640c23a62f3a-a38291dbe65so198896766b.3
        for <kasan-dev@googlegroups.com>; Thu, 08 Feb 2024 03:12:07 -0800 (PST)
X-Received: by 2002:a17:906:3087:b0:a37:726f:86b5 with SMTP id 7-20020a170906308700b00a37726f86b5mr5078717ejv.65.1707390726900;
        Thu, 08 Feb 2024 03:12:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXPANIcADAnwuUidYhTH8qIvR2oO3w9zWMEc/wod9D3vlMeXNTH9cfsc3EMHdjG2qhhfxPTqtMMo7qumpoghsas6jKFYvvTWZYrrA==
Received: from mail-ed1-f42.google.com (mail-ed1-f42.google.com. [209.85.208.42])
        by smtp.gmail.com with ESMTPSA id tl8-20020a170907c30800b00a387d9d6dc5sm1659048ejc.174.2024.02.08.03.12.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Feb 2024 03:12:05 -0800 (PST)
Received: by mail-ed1-f42.google.com with SMTP id 4fb4d7f45d1cf-55fcceb5f34so1801863a12.3
        for <kasan-dev@googlegroups.com>; Thu, 08 Feb 2024 03:12:05 -0800 (PST)
X-Received: by 2002:aa7:de11:0:b0:560:5f1e:f416 with SMTP id
 h17-20020aa7de11000000b005605f1ef416mr5940766edv.32.1707390725562; Thu, 08
 Feb 2024 03:12:05 -0800 (PST)
MIME-Version: 1.0
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local> <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local> <20240207153327.22b5c848@kernel.org>
 <CANpmjNOgimQMV8Os-3qcTcZkDe4i1Mu9SEFfTfsoZxCchqke5A@mail.gmail.com> <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
In-Reply-To: <20240208105517.GAZcSzFTgsIdH574r4@fat_crate.local>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 8 Feb 2024 11:11:48 +0000
X-Gmail-Original-Message-ID: <CAHk-=wiJj0AuV930QSxdBPz1RFSdLPdcxbY5KjqevKMAkJdBrg@mail.gmail.com>
Message-ID: <CAHk-=wiJj0AuV930QSxdBPz1RFSdLPdcxbY5KjqevKMAkJdBrg@mail.gmail.com>
Subject: Re: KFENCE: included in x86 defconfig?
To: Borislav Petkov <bp@alien8.de>
Cc: Marco Elver <elver@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Matthieu Baerts <matttbe@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Netdev <netdev@vger.kernel.org>, linux-hardening@vger.kernel.org, 
	Kees Cook <keescook@chromium.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=Mo5id2g8;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, 8 Feb 2024 at 10:55, Borislav Petkov <bp@alien8.de> wrote:
>
> What about its benefit?
>
> I haven't seen a bug fix saying "found by KFENCE" or so but that doesn't
> mean a whole lot.

It does find some things. You can search for "BUG: KFENCE" on lore,
and there are real bug reports.

That said, there are real downsides too. Yes, you potentially find
bugs, but the act of finding the bugs might also cause issues. And
that means that anybody who enables KFENCE then needs to be willing to
deal with said issues and have the infrastructure to debug and report
them upstream.

I think that's the *real* cost there - KFENCE is likely a good idea,
but I'm not convinced it should be a defconfig thing, it should be a
conscious decision.

           Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiJj0AuV930QSxdBPz1RFSdLPdcxbY5KjqevKMAkJdBrg%40mail.gmail.com.
