Return-Path: <kasan-dev+bncBDQ6ZAEPEQIPPXVWWADBUBAEWAQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 170B689790F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 21:35:21 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-41545bc8962sf654285e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 12:35:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712172920; cv=pass;
        d=google.com; s=arc-20160816;
        b=eN1OfRgMJQqsSJVTBba12LqSANgMde0+ufX8rLwRiXoB+52JoAHLjY+KJ1M0hVoBFd
         tb8XtV6LtdBiCQm+OwdHazeUe9fUBW+SH0pyPXbovYiFRwzXQea6Ty4AZpci/u2P80AA
         N2zGl4M+68Nkj77J6Kwfn1W4LI6jWC1om/ty9DfE3ZJu0IJpzBDqFat2wUexPgf5AsHq
         0lfhb8TpsPUEYoBAK6/h+KEBT8lxFPlEB2ZaSrH//7OW7/YVO8POFXr0b5B61kbhyoTM
         lBSqtvxmYx8UcjA/Old2mh9riLRAQ3bKa9KDxnbl/IGocHRENkmPDsznyzN2dssgaRRp
         /tOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KKBBkUcZ3qNpKHln+OG0aXDgUR36JDCCntXjlQFkwgU=;
        fh=/xqZTa73g1IsE2ObsmYjrlf0JtxgJ9bzEwA9PLcS4PI=;
        b=u8m6xiNQj1IYgWuqX9arjAltjhrBuIctDX1rv4mTDXSMJPrNSnT4z/HxzjRkejRRdp
         fkyAfQwXmNHly44iVqWrr7CXziU/fmkHXpvuA4CHDR49c7ZByaLB4Lmb5rAndVSPbDW/
         Hn7OnDA7rBwnMM3gpMQoTDS1hm6cENoBLP9b1bRyvsZlyMlABXNnSDmoOYZot19nOl9j
         u31o/AOI5SRvnqHd3DmddA47tq4oNm2c+hFKU1+u3hBWfqY0DgfCJc7F1Q4+f0qSXeBI
         KbA70YFHRrdsyXPaG8cMtB1YDig00isF6+G4TwMz3AiXFQsM+x211dTvCpR30iIB9laD
         LH0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4R7vbMW8;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712172920; x=1712777720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KKBBkUcZ3qNpKHln+OG0aXDgUR36JDCCntXjlQFkwgU=;
        b=ozgjkuYQOXdA1OJNKJE4GP7+mysUrYI6kNtMSlMHigN5t9/lcK7XaiCfvnv4olQoNi
         D4aXgl8+Q24QneOJ6hIg0EZtPJrpePy96tqOX+9PJ2C8awVpl+o+R3dzT7lB2jrOrYMg
         B7HKaW5JIq/Ar+PPT8+LeiziMFdGUk8CN3DwFxKbzrTrAzoZ5TWt0GQOdSySfavWPjOw
         hL8EQkknFPQHrM3CG25sGCVEI6CUjNbiU7lqslunVK8JzkZ7WB7i2XWzPAtyCGdXxyKW
         DfdIyvkgTeEJz1m3DPqRoig0hIwYUa+C1hVCfYeROwG/utpb+C3+iySF6q1nXJkw/NgA
         5oNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712172920; x=1712777720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KKBBkUcZ3qNpKHln+OG0aXDgUR36JDCCntXjlQFkwgU=;
        b=P09g539HjUOLgJ3MiJWxFBpRkCOIQFLreux2WBbMYC/MnrIVmxIkrbE4TAhp1tbEcc
         EotiS0jQDO1TaM1itOHlqtYsqsHFo89hNdCXMpAO/EMXAsLMGNz4q77y2uKVxQZpqorx
         UC2RDJa0jghf97SMvwlsDTLqR2TyfTQY7m3nVWZ8YUvkK6ZWzdY52o104Y6FXRRGv2Va
         dRKPexZkbEagcaiY9Xm1/aZ5zHETeIK302fI4k8IA3nq4xYYmWfR+08sGvb92t4qKv3m
         EISx7IbtALqkfxTC8XphW/TSI/180W8E/yWv2sVcBtTxw1aciAviNahThl9kVmUA6bbs
         UWkA==
X-Forwarded-Encrypted: i=2; AJvYcCUIUIsIHB7Nnc/dWlbB9XXRcoVEpvCfX6AkC8uz9Ip8XhE8VlNroKOAqCFT0sAsxXeu33mEykh2+1F1hX1M2I2urUyW7sNy0Q==
X-Gm-Message-State: AOJu0YyUlx/KC5WodMSfOu5vxgicXMnXXNwKlIeKtyWHw1O8gseLAfB6
	IGn2ObsA7Lg9Th7pL4YzFKGA8CRcYx4UZQ2iTqvrCz6OjaQi81vw
X-Google-Smtp-Source: AGHT+IEC/KjOM/GukUifd2tSaCdRemNYkX5XDyE0pPDEE0BtAqrU4dDJKKHnVkLTqSoVIeKuBxONaA==
X-Received: by 2002:adf:9bc7:0:b0:343:668b:be04 with SMTP id e7-20020adf9bc7000000b00343668bbe04mr308632wrc.3.1712172920184;
        Wed, 03 Apr 2024 12:35:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:452e:0:b0:341:cf9c:18c8 with SMTP id j14-20020a5d452e000000b00341cf9c18c8ls104148wra.1.-pod-prod-02-eu;
 Wed, 03 Apr 2024 12:35:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsN5eYTq0mHHcdlhZ1b6w01LzS6NLw/bFeMjPSqRyByc1kimXE/y4ZqZJkJh5HQ+7PjkjlKmKyh6eIKFLzmkAKVMhRapQi3m9fUQ==
X-Received: by 2002:adf:ab03:0:b0:33e:bdea:629e with SMTP id q3-20020adfab03000000b0033ebdea629emr314642wrc.37.1712172917966;
        Wed, 03 Apr 2024 12:35:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712172917; cv=none;
        d=google.com; s=arc-20160816;
        b=qmrl3SFmdogPlmFQpeJIA9tUrPbsSwbIddxViOoCUPrLE+1ISOkyVAjL2eOX7q9XKY
         hFyGJg+OA4R7RF+/khDVPYeER73hvay/dnyHG6dMV0hVHZ6mYmNXOXPh5YDgJKALVE1F
         kqkXxIdk533tCIOHeHRSvckdorQV6iGn99FWcFIlaJSq8joDLjmVBWtp36mNgQIRsW2U
         T1vXYEc4uSfdUBHgzFM1HDRbO6bkxD93qcBtclSqqldCPaQvKX8KGsFl0+ACXHU4DVbH
         8f8SrYx5fmebMYAlRQGdyP3+y3ODdQwQMvpvL1b/k2sfdGZSnj0xOfFEqEE3DNqccCPX
         BKMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wz+XAmCjUc8PDsaYphxSsci9OJCLtebQHEYs8FmStqA=;
        fh=jLrso4/RgwFVVvN0gKB8yqgoPP+uHeVeSX4g+h5gZO8=;
        b=zlrEWpJKGLFou8Gci8h5tAqfDZaVtPIXu47CDC4QAaRqW7pU9Gz0TiZyD315+nS+HT
         iuqMD2JSW6xHy1NwDJRtoZUCdSai358RIRImER74wI7oVduqixyUDNLb5RmoIzoMJqLY
         Mu2ownpmUgSsSlmJzuIlCTs7zKey3uzgeC7mNCJFFIpA4BTrczwOmlysS1icz5LRqDa8
         Uxb6dXXch6BnQwjwAAPXsgX9ySwz8iJTZMqyx610NvndRl4/YI//qA3LdOYLWgh2wfr5
         JNjVkYfADzqRlthHjORhiy0Y3tMW0clI/ASh8npwbbczBX97RmI/05Atp/8GvVf0o1bJ
         ttdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4R7vbMW8;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id k8-20020a5d6d48000000b0033cddf15870si501110wri.6.2024.04.03.12.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Apr 2024 12:35:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-41549a13fabso925e9.1
        for <kasan-dev@googlegroups.com>; Wed, 03 Apr 2024 12:35:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/zCDUacPbMiGfzN7jMYNUGVzXmGl46APZ1P5IcJVN3oQwLOQ28CRMt74P0u0FzYG3VClfPnXTJAhn3viLIZ7BJ2sk7/JwknWahg==
X-Received: by 2002:a05:600c:1d25:b0:416:1eba:175f with SMTP id
 l37-20020a05600c1d2500b004161eba175fmr299989wms.6.1712172917250; Wed, 03 Apr
 2024 12:35:17 -0700 (PDT)
MIME-Version: 1.0
References: <87sf02bgez.ffs@tglx> <87r0fmbe65.ffs@tglx> <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
In-Reply-To: <87o7aqb6uw.ffs@tglx>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Apr 2024 12:35:04 -0700
Message-ID: <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Oleg Nesterov <oleg@redhat.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, 
	Carlos Llamas <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4R7vbMW8;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::331
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Wed, Apr 3, 2024 at 12:10=E2=80=AFPM Thomas Gleixner <tglx@linutronix.de=
> wrote:
>
> On Wed, Apr 03 2024 at 11:16, John Stultz wrote:
> > On Wed, Apr 3, 2024 at 9:32=E2=80=AFAM Thomas Gleixner <tglx@linutronix=
.de> wrote:
> > Thanks for this, Thomas!
> >
> > Just FYI: testing with 6.1, the test no longer hangs, but I don't see
> > the SKIP behavior. It just fails:
> > not ok 6 check signal distribution
> > # Totals: pass:5 fail:1 xfail:0 xpass:0 skip:0 error:0
> >
> > I've not had time yet to dig into what's going on, but let me know if
> > you need any further details.
>
> That's weird. I ran it on my laptop with 6.1.y ...
>
> What kind of machine is that?

I was running it in a VM.

Interestingly with 64cpus it sometimes will do the skip behavior, but
with 4 cpus it seems to always fail.

thanks
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99%2B_GDS57HAF4jZ_Q%40mail.gmai=
l.com.
