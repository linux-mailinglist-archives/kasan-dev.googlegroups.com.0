Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBMNXRO7QMGQEXVUO5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AE31A70706
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 17:37:08 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5495851a7a9sf3048624e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 09:37:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742920627; cv=pass;
        d=google.com; s=arc-20240605;
        b=GMJpHwi3rKlQKtMqvW4zaYjIsL75pnXo/EgreE2stRMYmk3P+AoMSX6/3BPs3rdC4Z
         ndl+zDod1NAOMIridnXfDo98vq/gwCR5nEs8JWkCk061FHSRc69WZHAeLoehi9wF/JMF
         0b2vljIIHlnmhHnDLufFY12nkWxTbDL8AuWcxKGlI5SxZT+c840bi+SaPsW2R5JK7Sik
         inFouAI817DfxTSivTT3i0Ync8AopZCHRc82rTi5tW9Sq1F47sFsMQRY3GTFQpSNAopg
         856kMEnowLPqlaCX3RQ2NhYrn5VjpuxCDy6s712B0PuInyXI9Jc/JfBk5UCnd4rNP14+
         oXqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n5qdkAzhG9Lr7OTwZBj6LG38eEClIWNthpGULZ0CIFQ=;
        fh=NqSjlQXbUx3VduT0oSoBQzJbsC3bo7jKpgH8qfgxSDo=;
        b=aQu4QfgPgzDqGeurBYxOX3x1kaqZLiAcDmznhHyhQyobRi4PW1Sps7ecESS6O4GS+2
         zOH6cHrBe2BuONxLOmmLyDV7YEjBD0HUrbiS7VW0X8REPlRJXG18Y+wjcnYlvFZZAtIv
         e/LcoH3trvZGCiAgHpisHp0IhQnvnsmmmkK2vd2JO8s+CIyXY75Yw3jJU+tEI5truWkb
         o3EiVcw2lk6nFHMZ6GCRWXOhwEHdQ6QeaIccnADgTcGofhWmksClq8KLMneMANmVPT6K
         qbpJh3NSNrSTa671QXFXz59mn5DCRRP/rJlnGOSsjfLgkxx4TWcdVfPF66M7y+/5Nv0C
         n0ow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Lk+xu8Hh;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742920627; x=1743525427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=n5qdkAzhG9Lr7OTwZBj6LG38eEClIWNthpGULZ0CIFQ=;
        b=k2t08sVcwQGo+fiZ621wQ7cT6P0a4aTD6FEVFb6Iu7mvBIFMw2ZpzUsomHqkmDAtqH
         ak5Yswm/jhQFfIRoCAu2WOwaT5j3GVOSZLNjJd0PNB6A9GxeDQc5cVAfZIEJTHJ3Exmj
         WWbSPibYMGg0w0GmBttmY+KmZISUfOw+qsG3NDppTiKz9el8otE4u0gAfgQtO2uqZQJW
         uTFbd1Ud4jsrq8jhKZI44p6frQOiiRw4zujq3nxXUhMAzbgtC65QdngdJ2XtmwTknF5w
         Q1Sa3UopbGuRaexX+Tbn9QT1thE7jp+r4jnpM7yo9j0mNDLeiefVsUZVBI9kaKBN1nn0
         j62A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742920627; x=1743525427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=n5qdkAzhG9Lr7OTwZBj6LG38eEClIWNthpGULZ0CIFQ=;
        b=uVgTkFairu1lRvZ3NOaD90dVoJ0IsDYjrxr6fGeM+6BD/zIJrPhwu5PgGCxieDb/cI
         UMWQKoy9cg0fJXwk9ozN7igI72J24E4lu75ApjUvu+89i9Am2d8GsUxG5Dy7iG6Dccrq
         9gjGVs9kNZrLgAF4nU25uWcZmjTJPHthd5lu+KW93BXIJAebWo/WVxJqmLdpdNQkRQxE
         BvOECofvkQ14DkcgJokymicEHWVM+jcvOs3mWK6SU/rWst/mqJII4j21rcwQSNH3wlML
         kfaWq8ezwHRGmwXKLlaHm88TGH9wyGkQsusPR/hMHrhQjtsTVTNffDsf0dW4EwznIclX
         Znpw==
X-Forwarded-Encrypted: i=2; AJvYcCWW40smuI7OXfhrEQAFUzidqusOg9OfGVg74UfhxmhbcCFUR5ogB/rdzAjSfOQDjRNXCRubOQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx2Ng8WfAPNBll2oVt+9iTrXLpxXlL0GTxxT4htMTwfrXXmxYI0
	FerjY1M4bBUDvlr6E7sAcUTxl+aL0zB60bsuGgUlQSsDA1splS/W
X-Google-Smtp-Source: AGHT+IFovylqTc+IWJf1nLq2wg9AmoPNk12aODeqYooShOXsy8ELWF/X+qkXlcJfT6icCGuxfe7KAA==
X-Received: by 2002:a05:6512:239b:b0:545:5a5:b69d with SMTP id 2adb3069b0e04-54ad649a7c1mr7608914e87.31.1742920625930;
        Tue, 25 Mar 2025 09:37:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJv42Ke+n/Ib+0QHdSckV1A6i3YwE0DKx/pGyZFqufH6Q==
Received: by 2002:a05:6512:1044:b0:549:8cd0:9b79 with SMTP id
 2adb3069b0e04-54acfc7a2efls404591e87.2.-pod-prod-04-eu; Tue, 25 Mar 2025
 09:37:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuqmE1wdd9ccxspXAn3X5of3SQOSy8L802JZeA/UVgkK2DvzV0TJ2ROuFlgvGjP7cyQOk9teCFqHA=@googlegroups.com
X-Received: by 2002:a05:6512:a8c:b0:549:4df0:76 with SMTP id 2adb3069b0e04-54ad647b434mr6216226e87.4.1742920623198;
        Tue, 25 Mar 2025 09:37:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742920623; cv=none;
        d=google.com; s=arc-20240605;
        b=caY3y54Qd3tdSg1AfyB8ULsa3dpG1XNauR762Fe0TNXINE5t/TKEErgrSW9bfO1Vjq
         VNYaGppa4bWT4tJP6XYc9CSfTHobdgFwido3Eex/p7+pkxKmqnZZobncRLWEKNpH4FVU
         8I7wGPGvzkMGCzY4ao6Dqo/7KZQ5PSb6WUmSJO+79QDvdK98jyNyudAOblqbq14wmaG2
         x3A6Y0gnNOcD8uEPgoFEe1WjNmQoCoZIGDq78lfyttg7nL2nFbdhekSjoAN8SlzVoPZp
         4RFRLcRrf8XZt3hstSVIfC+86xjqPXWY9wh62zm+J63yau9eCZ0TkqLtqgph+e+dfZXv
         YjFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cdtKBuwq8KD1n7kXxsXZzrCM7kAgY9mfaSLYLssvPX0=;
        fh=yICGZ+sYwxUnhFBK6JqZks7BinYckrL1aTqkfIEEbDc=;
        b=My0K6KqoI+mbUl3m8K/QJvFRAk6E4J3F13HE8/JpArBtBMPR+vQGr9n6M4Ts6Tmqdl
         XJLEzUA/xzq8Nqstav3+cBkMt6vGDJSzDuvTZlzVrONlySAQIZ/kQlZL++Ts3qQfYnu4
         FLbfO/826kKlfsPuMwtxw0f8KIJEh9dqMV9RFU9PJwR/+wSDim3RpjqbZ0JOgMJRSQ6J
         JZZb3oL2FInsLv6NXIqjtsYn0A2f6OgUU3KGFnSDSm1SR55LajGm+YO/0Gyus8OJtQSm
         mNcM+0Jr/U5eeNhXDfnPBbdbCkROxpOwvysWZ8QALcg4A1lmGOyTdAkeQg8acsJhLuHs
         zcfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Lk+xu8Hh;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30d7d832817si1758761fa.4.2025.03.25.09.37.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Mar 2025 09:37:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-5dbfc122b82so122a12.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Mar 2025 09:37:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWyII/+qTg36FQ5rD8igJ6dVkpfU+HKl+1SueY6X24eHgJEUSPoWwH/5ScyLP0eJaZK1lpOlnVsz70=@googlegroups.com
X-Gm-Gg: ASbGncsu7hzXOKbSndz2XHJmNv0VGp/BYpgowLTuYS+ULN8B1lycNsH1acm8+0ZmsmH
	a70hmvsfrFqO2R1Vy2CdMHmSICZifGLe0FVrpgm0EIRCiiuhbNZs8BReYJi7y1AmRrthQaOjVO4
	/3mX3YLojJhP3EmYULHkO7en3HT3LP8CVappTrB50HahBy+mkDxkcROg==
X-Received: by 2002:a05:6402:2058:b0:5eb:5d50:4fec with SMTP id
 4fb4d7f45d1cf-5ec1d8fcf0dmr312539a12.0.1742920622152; Tue, 25 Mar 2025
 09:37:02 -0700 (PDT)
MIME-Version: 1.0
References: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
 <26df580c-b2cc-4bb0-b15b-4e9b74897ff0@app.fastmail.com> <CANpmjNMGr8-r_uPRMhwBGX42hbV+pavL7n1+zyBK167ZT7=nmA@mail.gmail.com>
In-Reply-To: <CANpmjNMGr8-r_uPRMhwBGX42hbV+pavL7n1+zyBK167ZT7=nmA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Mar 2025 17:36:26 +0100
X-Gm-Features: AQ5f1Jp1Xe_G-CxRRO6kwph46Q35uuQWx_DCrGXZTFNG3il-9h0KD0k1zhEGxuE
Message-ID: <CAG48ez2eECk+iU759BhPLrDJrGcBPT2dkAZg_O_c1fdD+HsifQ@mail.gmail.com>
Subject: Re: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
To: Arnd Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Linux-Arch <linux-arch@vger.kernel.org>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Lk+xu8Hh;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Mar 25, 2025 at 5:31=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
> On Tue, 25 Mar 2025 at 17:06, Arnd Bergmann <arnd@arndb.de> wrote:
> > On Tue, Mar 25, 2025, at 17:01, Jann Horn wrote:
> > > Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrast=
ructure")
> > > Signed-off-by: Jann Horn <jannh@google.com>
[...]
> I have nothing pending yet. Unless you're very certain there'll be
> more KCSAN patches,

No, I don't know yet whether I'll have more KCSAN patches for 6.15.

> I'd suggest that Arnd can take it. I'm fine with
> KCSAN-related patches that aren't strongly dependent on each other
> outside kernel/kcsan to go through whichever tree is closest.

Sounds good to me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez2eECk%2BiU759BhPLrDJrGcBPT2dkAZg_O_c1fdD%2BHsifQ%40mail.gmail.com.
