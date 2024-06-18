Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2VXY2ZQMGQEJVDQRTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8539790D578
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 16:38:36 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-703feb93e29sf36421b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 07:38:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718721515; cv=pass;
        d=google.com; s=arc-20160816;
        b=tqEGy3UaDyC4QFKJfmEb7pUMCVBvXBgKmr+CADlOimz2+FEt3TrFW4Vyg78D4bqUZ/
         4GGny6l9m8cN68z/QXpR7w7O3ftupkdmq4aVm86aaaXQsXssFe3dZrM8lil8+GXPGBBH
         Mr6MpbZC7Mxvzc6XLJRyq7ooIKyJ9W8NtI2c/dxmmHN/+XrzguIkGCNz7ZadQWPyvLqd
         aV0RTw/MDp2Ah0bS9Wb5t/cmqg1OWV9rHy57NcY0S9imHQ2cX4mCxOf+MAE16UtRT9d8
         C6Y3fOSQi3Pu+4QkDd+uzy1BFkQDR79oNobMvndQRW60oNOv1SNzow06q8FMIlhH8j8/
         JYtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LwiwkQn8CbL4S7lwqOR/7OyLPPFYBLRVhFrNK1t+cJI=;
        fh=CgKyU/Hfg8fxol/b9s9q8Cpu41ZQtJcL6KvgSnIDViQ=;
        b=PJKx7AUB3rKDWE50cpk/PyrSpoZfryyu9PpeROrJ9Af8FUvOJI22Kf4JKKOtpv04Kw
         SzjgDufe/Rso2ET7CiTZJ1mWjwzV7aedTBZeeTLHKDAbetvTLtzd9PmMr6Xj9bndS0fI
         9amHijqRmIk8hVDeSOsDR4D9+SbtvHg2Dj5hLKo1YgvENKO6JiaWpLRzWfZnRVrNDP1K
         4opiZ6uDiHPF5Wko58yNluXQIqJzxcOjBXzw9XtuWIOjBDISC5Lcw3QGgX/of5sPzUwF
         EsHz646ciqqV156vRSSdMqxT8on9Zl3eGgR2zxTJmwujDI1p92I7qlbinK05hlVp/58v
         16lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0EPRLuXO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718721515; x=1719326315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LwiwkQn8CbL4S7lwqOR/7OyLPPFYBLRVhFrNK1t+cJI=;
        b=Eyq+fLdct7eEn7hfiYVl/11U+EtSprUNSrTSpqCMq2wejJKTVBvbfLz4dQ3qi3e4hK
         SM1Cs2mjZT/mqpfDkVdn30eqg0Yo/SQdjc+hTwYKioCIOjWjnHpk/gTbe3lXe2I62N30
         c0PZP+0gscUSITVVaeaIfx0rY5rD0ksszZpdavbpNBlvW9bn73YCqAURv/FPNNtqz5mw
         a3RWljC7QzHfFXc1FYiZx1a1Lh7CWKElX5MzlmGEKpwOJwhfl/bhw3mu7X/REhQwSd26
         +GEe4E0NJPqMm/rtRpfJ8jHXuaGYed5ariRZ0nwYlbMdAnLtmpWhJ3xhWwrDQbnDBfdM
         svZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718721515; x=1719326315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LwiwkQn8CbL4S7lwqOR/7OyLPPFYBLRVhFrNK1t+cJI=;
        b=r4bdv7W1/iRKv9Hca2cF6ioZoY80mPxi0zSjbuBKg3tFuSxeeHAUK/fGo1QjMT0L5+
         wGOnKfi5LRg91Ul2Q7t3hohnuRfRLLrWn6V04fjlip7vctntXDfeBGm21Mgr7DTHKknY
         RoBOnstZOetr1o/B/PWyPjRPcInY6daHTKAx0aIzkJPNA89URFiapQl3S7+80zpXtqNi
         sWIchhaRDleCBFe7ZwG4g0NOL3dUHNrfmZ/LtwW7/mOHC9pM0+zpjAnp8lv4biuS2AWN
         ZnNut3+A/zHjrxIrkjC9Z8OZZa2CFc4WtP8I146CMLOprEs9o6x+hhvQbxUSq7kKwNvJ
         uiUw==
X-Forwarded-Encrypted: i=2; AJvYcCWDKg4rIDhAjdHTyQ8mveK9GZJUvc8TW2sASFVruj6yGkf0ti3hkgqX8YhzOgwm0Wt4kE9BaQS7PGeYRcGOD8fEUGPW+9qbYg==
X-Gm-Message-State: AOJu0Yw+weCaPal3g6y2ewITowtvEKmKFS+fnpyqLf1C8GlLzvYBKl/v
	GeT9BYAxlIA/qDdbXbVpRMy9QC1dYZOGobdhoyv5RS/urrGfmJXB
X-Google-Smtp-Source: AGHT+IFGiyfL0eX4Y9jgMupgcRrDkI/oSkrijZuQk6N4nE8/HBmdsxpJ52nsBS81rWCaNtN+FkPlAw==
X-Received: by 2002:a05:6a00:310d:b0:704:23c3:5f8a with SMTP id d2e1a72fcca58-705d711f80emr13852471b3a.1.1718721514892;
        Tue, 18 Jun 2024 07:38:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1795:b0:705:b591:29f0 with SMTP id
 d2e1a72fcca58-705c9457069ls3581138b3a.1.-pod-prod-06-us; Tue, 18 Jun 2024
 07:38:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURxsDdySyA+eUXzkNDq+w6A/YWH9uXyr0ljrtWMbg6q9NPE37RI5iGAqBClP/j1KSAdkgbH3eB0631DiiMbq14CF2PErNMCBZ7nA==
X-Received: by 2002:aa7:8494:0:b0:705:bc69:3855 with SMTP id d2e1a72fcca58-705d722cb92mr12552490b3a.34.1718721513352;
        Tue, 18 Jun 2024 07:38:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718721513; cv=none;
        d=google.com; s=arc-20160816;
        b=fhgsSe0mbgtoAMW0Q5mp4cBxzxhl6s4Ga5MpQ4e6Rsxth6ah6u9DT6CjgPIQqI/H6A
         NNQJwqaOvPCFtdotV3Hr5ARF9vioxVshrWdNmj+0CW0TBH8D/PBDnnVYSMrSAxIdswTP
         xyfckZTiwp3IS1I5FAFeSoZ91NzPmm8NcN7rrQg202koFDhQIBf7akpZcEl/vatozFhU
         Bn2lrkxEBgfYy+g/szqU+r6B87z6Qor5XRsc58BF+lFNFbfMtaq2P24x0nKfpqmFTijC
         p7N59nvaF7Jz8SeLi5gtCQFTfps6XZPcDFgy+PIjzyPVyTvDq6Gt4AlVPOw8hYLJgGIo
         lg3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=asXpl0JeYor9a6fnYwHucBKXJR1r4vtn+68cuYeq1jQ=;
        fh=3qpuQDrm9/y5a62IlY5QmWanzivNafjnf0KS90vEcBo=;
        b=aJxMDMqCzDBdHoAb/2IAbBTld3VQaEq8xu/7iWuqcZABMB+rdNZmYNO3ToeHnvDSMJ
         BE/l3RQcR9Nfbqsb+4SdM1j9/M5WToxmE6KLRlzeQA9Pp2uwhygUZth5L+YxzZIPK5x8
         c82Ud/OIhLiS6r5BeqZjFnLg69xEAQUiAb/gPztwlveAWJjXXkIepP/WdlYX0MwbQaWZ
         +DsCjw8wMcgvCUtIMMpDI8mmUeo3su7hj+ugi3yXD+iDwz8njwd0VtN17N1RiK9zmKr6
         iC0MLdNk/PXmqKLXMtcocFLc4vgAsjQ3pGtRo+rm/8I+A2NDj47sfRwzy9VTGEoYt0sg
         l+RQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0EPRLuXO;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbb1c94si459259b3a.5.2024.06.18.07.38.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 07:38:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-6b072522bd5so26438556d6.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 07:38:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVA3iCm1s9U07+yGVxoIGBhB13msH9xC3VRvIRKBIC1aAVny0Te6qpSZnuAzmT1BbZmCCkLjGq1156wYdxMKsW/bzXsH4d0qYfVug==
X-Received: by 2002:a0c:8e47:0:b0:6b0:7864:90ac with SMTP id
 6a1803df08f44-6b2afc6efb7mr135971756d6.11.1718721512230; Tue, 18 Jun 2024
 07:38:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-15-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-15-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 16:37:55 +0200
Message-ID: <CAG_fn=UZ+gCgvgYtn7=p0o8P8sj+iDkD5t-PpihMNNN1W33XyQ@mail.gmail.com>
Subject: Re: [PATCH v4 14/35] kmsan: Do not round up pg_data_t size
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0EPRLuXO;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> x86's alloc_node_data() rounds up node data size to PAGE_SIZE. It's not
> explained why it's needed, but it's most likely for performance
> reasons, since the padding bytes are not used anywhere. Some other
> architectures do it as well, e.g., mips rounds it up to the cache line
> size.
>
> kmsan_init_shadow() initializes metadata for each node data and assumes
> the x86 rounding, which does not match other architectures. This may
> cause the range end to overshoot the end of available memory, in turn
> causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
> return NULL, which leads to kernel panic shortly after.
>
> Since the padding bytes are not used, drop the rounding.

Nice catch, thanks!

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUZ%2BgCgvgYtn7%3Dp0o8P8sj%2BiDkD5t-PpihMNNN1W33XyQ%40mai=
l.gmail.com.
