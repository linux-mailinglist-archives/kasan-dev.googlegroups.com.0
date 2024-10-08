Return-Path: <kasan-dev+bncBDAOJ6534YNBB4UVS24AMGQE4UROE2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6719957C3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 21:41:40 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5c8842f6339sf4610244a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 12:41:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728416499; cv=pass;
        d=google.com; s=arc-20240605;
        b=CWHpgEqzLP0oLkttdgf6/kWopSILS9NgLecpZJRx0htgoC/PKIHmLJ94lpb3qrhKwm
         Ymbfy1SlqZCyDf9YX3hGVHS5wJ3j9i/tAE7Z3tTz1sP1bHpJsaym5RM23y9SKHvc0jm4
         Z9tKKNqBwSTogmskvsDFQ/HC+RSWYb06j1fhNwXn0OJoe/BkdLlZecYNpsCk60CZ9LFX
         XLQKc4kaYv9jdrfEp72iRnnq+D2f6r400sERh/7MbCU/DWSebCleZUTfcK8/ggGRNm1g
         pxBvkXOECu/PFyXKIRPPT2s/gGbycD0mAli3803b40Vi3InLALwQ+eULDEbqKsuqCi4b
         qPQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vTe3WmZhAEHGaOYSufHE1XSvW2ZvEDXkC+kT+kL0sts=;
        fh=IC8pGdzbmNV5DQHiYNun6PO2Tzr8aH3sNStQV8KkIRo=;
        b=kRxr3xiyAqo8g64XQTNc3Sj0DgU8/E7dwAJIkWffkZdoSII5b8WHH2xl1hjynjx9IQ
         KsnuX+CO0Jc+NeWthq8JXXZcH73frFtGeFnZob3EOLFigslwgZUIcvJXJXHKJhICFXVI
         cmBplH/uZzOqYGWJ1P3GiE26Q5v2a7WV1u3SfIo/hwly5zpFW3Ld/16PqbK4gxsNXbNF
         Zz6F7nuQ3BkolBhVLI9QONvJ3UlwFPqDv2jGX9iQsOGpOBCnxm7LFj11TPrcYgNomvXo
         OOLn3YnK4vRjx4vScXxHe7ICzEHvhnMGsqxHwWBen8EAp8FSKE/KP63cSLwBdUlTuZe/
         CmOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UyuTpezv;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728416499; x=1729021299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vTe3WmZhAEHGaOYSufHE1XSvW2ZvEDXkC+kT+kL0sts=;
        b=qTr/i8duXXx/NL34SUkwfMewdGCR2/HI0opyOMyqgU3jtwjoDUctiE5rrihR46Rhgp
         MkIFTbHUcJmsxzaz8CeIGWqgxunz+c/v+VHjVxpEh+EIFOvTVvN2F22Sfi4r1mJZqr+i
         nRGvHRrdzz0ljotapIRuD3FC0S+Qs7XXzGLUQK+uwFaUvjZTA+Yeb107FY4c45w1ApdK
         2bwcyysofJo5LmtRH7sc39Sh+KLwN5Nc/eDkLddGIFqmriOfrWVgp309P2ggvbfwnkMb
         3FuTHahGS24Dw6wnT3ROf3esbmVcbEvQ2QMW7w5N7WhK5sSvzPm02bMQZCUzKBqfNzG9
         O8Ug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728416499; x=1729021299; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vTe3WmZhAEHGaOYSufHE1XSvW2ZvEDXkC+kT+kL0sts=;
        b=RSm6Th2qMxDrkn+UgjA3yO15dtU0LnF4tB+BmZhdtE7WSbhsoSmiclkRRimFoLM4y7
         rjPLfMxG6U8y1aV6FcO7R81KKtqxyCYoJcecYj7DsqdR2jTrPemUBI2hvq6sgpN37/16
         YLU9M9HB8bV9bxeJqY70a+gKHibAKT5p8Jk1z/MMnEmPPl1GKQJkTo7RmoRilNUhUvB6
         f8turrNzwqqnPVZnVspuseW60BTaKFCSfp+NUKuMnzZfXKfomICLQYXOEpcCCjCtkvy0
         BZlbHhemSQpGS4iRGf68aLsa1/1XYA0Qwn00YvgaJXaLrgxcD7jB0hdVezmTOZ+YjsCd
         9PmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728416499; x=1729021299;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vTe3WmZhAEHGaOYSufHE1XSvW2ZvEDXkC+kT+kL0sts=;
        b=CLle7x3YbJa7VnoYAHASesXSJG2qWdMpPG+zBxRQ67QXhnFJqrLaTQxm/uw65l71xn
         IvkvN03fZPNYGvZc57P7XQK5oo2yhNOIrGa0ZlV6R7uINDpSCe+xKDdPwmSA0B/aRFRS
         1CJsbuvsBXExIYPcMaTMsJfLWySa3cfZrOPClYbLf5Tn59AynQDPkeRe0cp1A5wpzmUZ
         v/Ky54E6NbowUwTArJFnQr3mvmqqJXNEg3axaqKh/a4UUkx1Gp1N/qnXfkovJ1QHMx+M
         oNykFYlfwLBViilki6F1Yy1EPUhjVprKKcjn4fc5PO7AF5faXuy6egv+z8Cz+uc4Ijyh
         G9iQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU26pmsdi/2/Sye2OZ7bf2BFvq0AH/GU15uGeALa94X/FTSQkOpPT6dzyFGNNjmd4oPv0FAYA==@lfdr.de
X-Gm-Message-State: AOJu0YxwmYI6qYhTJn++n/4xkBOzaIreyKMmoPymliZxlkPYwREkjHPM
	D8aHfPLczfHvCtm4GDuGHXMZOfvxX5Uszbq+VPKA82HMSvshF5O7
X-Google-Smtp-Source: AGHT+IFdDHhX1pSJfr2JuxDM5I97Q3hFRMXqRdvZP0CQgUPU5knJO56PA/Uzvxy/gm9Q+pchDSFUqw==
X-Received: by 2002:a05:6402:210e:b0:5c8:9548:f28b with SMTP id 4fb4d7f45d1cf-5c91d609f7cmr93996a12.11.1728416499154;
        Tue, 08 Oct 2024 12:41:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34d0:b0:5c8:acf3:12a8 with SMTP id
 4fb4d7f45d1cf-5c8ef418d82ls455982a12.1.-pod-prod-04-eu; Tue, 08 Oct 2024
 12:41:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6l/G/ylnXt6urPE/NP0wrJqP5SfRhH9Dg0xCN+e3W8sgAQq81WEp6Ay1PA5II8X4Dk94hEFMI72I=@googlegroups.com
X-Received: by 2002:a17:907:6095:b0:a99:46ff:f4e6 with SMTP id a640c23a62f3a-a9947000935mr1121046766b.61.1728416497251;
        Tue, 08 Oct 2024 12:41:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728416497; cv=none;
        d=google.com; s=arc-20240605;
        b=kwiJBs/cviLCEu7OaPC33IRQr14lArQZwV04hLlgENvlTZrM1ubyff/Edj57SBE5zJ
         R+KQA5zmxI6/JnV+mIt7slq+WjVxOj5EeKBv8bp9d4HYi+QcVYKqcS7qmpjCQ+ICzfgx
         7GwEDc0i5z7pglhParlXTwMKOHUvjjxT9xNcwp5FSHH+2YMkTF/TlCJt4bozfZdZGeOj
         c4bglqn0slUNWRqooFb2P5UexaQrW2ZAmHernqcSZjEwAqKoLSAruJj88uho94iIxMc/
         2S1A0a23pCa36tpmwxnFpoDJ9fkuQh/FLDK8aSmvqxVGMjgPG19pQ0oNiisNtjdvRmiZ
         fXGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ubbmBflcQYl2zP8nv9YP3haRuCtPw16r/0MycKENL+U=;
        fh=+U78TDdlh0vz9WhdoMya6fr+X/YtJXnbR5Qt3pNgyDE=;
        b=Q90l9odcmKe7PPStSKP6+P15iWxPvV2F3gbNu5zBx7hN0rqr8fTc/h3QY0a+zBmHz7
         bYaR3Y7L+3wEfBOWCClksq45Y8an9XYEuWYWg5qRxiEozJDlO/5H4o37O5LASoLywsAp
         UXyt2SqSmOfY0jPhQpb5lWOtIM1Qbn8H1P+xQwaCm9ivub12nOFmkHXXB6fPLW4XPNrI
         cHkTDt9ptyZIQPH4maBaCbf3pVmvQjVhAURgL29zyJpNy8/y9RvinFDPOYYULdpdOGGf
         fbsPqaBCW1OH5lfG+3X9a9d65yIeUV+mopN5C/ma/uZTnfQaoZjaWLpKfyKWvxuQk6FO
         EIIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UyuTpezv;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a995f2132a4si7113466b.2.2024.10.08.12.41.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2024 12:41:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5369f1c7cb8so6606074e87.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2024 12:41:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXnF4M1LwjVet47bvyr9cpzvDhaYol27T11vWS7ulU3NYn3tWAPANveO3u5fqpQqvqiLK/G+9XhTOw=@googlegroups.com
X-Received: by 2002:a05:6512:ba2:b0:536:9f02:17b4 with SMTP id
 2adb3069b0e04-539ab9cf41bmr8639804e87.40.1728416496101; Tue, 08 Oct 2024
 12:41:36 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNN3OYXXamVb3FcSLxfnN5og-cS31-4jJiB3jrbN_Rsuag@mail.gmail.com>
 <20241008192910.2823726-1-snovitoll@gmail.com> <CANpmjNO9js1Ncb9b=wQQCJi4K8XZEDf_Z9E29yw2LmXkOdH0Xw@mail.gmail.com>
In-Reply-To: <CANpmjNO9js1Ncb9b=wQQCJi4K8XZEDf_Z9E29yw2LmXkOdH0Xw@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 9 Oct 2024 00:42:25 +0500
Message-ID: <CACzwLxhJTHJ-rjwrvw5ni6jRfCG5euzN73EcckTSuM6jhoNvXA@mail.gmail.com>
Subject: Re: [PATCH v4] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, bpf@vger.kernel.org, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UyuTpezv;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 9, 2024 at 12:34=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> On Tue, 8 Oct 2024 at 21:28, Sabyrzhan Tasbolatov <snovitoll@gmail.com> w=
rote:
> >
> > Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kern=
el
> > memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> > the memory corruption.
> >
> > syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> > KASAN report via kasan_check_range() which is not the expected behaviou=
r
> > as copy_from_kernel_nofault() is meant to be a non-faulting helper.
> >
> > Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> > copy_from_kernel_nofault() with KMSAN detection of copying uninitilaize=
d
> > kernel memory. In copy_to_kernel_nofault() we can retain
> > instrument_write() explicitly for the memory corruption instrumentation=
.
> >
> > copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> > CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> > kunit test currently fails. Need more clarification on it
> > - currently, disabled in kunit test.
> >
> > Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1=
X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
> > Reviewed-by: Marco Elver <elver@google.com>
> > Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=3D61123a5daeb9f7454599
> > Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > v2:
> > - squashed previous submitted in -mm tree 2 patches based on Linus tree
> > v3:
> > - moved checks to *_nofault_loop macros per Marco's comments
> > - edited the commit message
> > v4:
> > - replaced Suggested-By with Reviewed-By: Marco Elver
>
> For future reference: No need to send v+1 just for this tag. Usually
> maintainers pick up tags from the last round without the original
> author having to send out a v+1 with the tags. Of course, if you make
> other corrections and need to send a v+1, then it is appropriate to
> collect tags where those tags would remain valid (such as on unchanged
> patches part of the series, or for simpler corrections).

Thanks! Will do it next time.

Please advise if Andrew should need to be notified in the separate cover le=
tter
to remove the prev. merged  to -mm tree patch and use this v4:
https://lore.kernel.org/all/20241008020150.4795AC4CEC6@smtp.kernel.org/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxhJTHJ-rjwrvw5ni6jRfCG5euzN73EcckTSuM6jhoNvXA%40mail.gmail.=
com.
