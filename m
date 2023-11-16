Return-Path: <kasan-dev+bncBCCMH5WKTMGRBBN626VAMGQEWD5ZWYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 918237EDD83
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:21:10 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-421b20c9893sf7518151cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:21:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700126469; cv=pass;
        d=google.com; s=arc-20160816;
        b=JoRbd3elaqrPOdEpGVjL1e6LO5If3jE+Y2tECopHG9RkTVrJjO78EQhnRM8YLC1M0f
         P+cPqjY85A7TjiYxY/KxLfLIHWSnDbck4letEwgG/2CNN2CJ7tb6t0VDh7SJmah0RlAn
         rD0lHY7XFZxTVcUD/4HzGwDQHses+IIzTDC79HcRQIEqnmwe6YaMPxb32zMN4EnQU4lF
         Vfyv9Jo8euevcin0Rw1Gvcgc3w0mYmtgOtIfPbLRubQOxU8n13NIe67ijZxxyDwJeMKy
         2eG78Dyz/d22gfwYpNL7Bp44fvlHad/inks5n9lIchnDzJIsXuG+Qy9gaKhhpOEL1/F3
         Z1lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cs7Ph4SuzNF9wHTfWlbPzBPkL4m5xkHnhpgTuJ/pVjo=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=uiEOjJgYu2Kw5p8NXyIDW6gsXEf6BCxjN7260fV5tU26RaRNUFTj/wTKmUvrNv9+RD
         wEQEJ7kmB7ICfLijZcbYqPhymZSE3ZDeT/UOmn04Sz1YigVcW1zXVfyGio5K64WNlLSr
         d1/YYSuqe303xqMqzFcCNe/P/mvqXLXOpmWr+X+2lUkySIiqracQl2jogPbTFRts2bCq
         zYX15ssP7vdM8UKh3R2jyfbS+GkpALWyp0LT7Yvtux262RzYfNp4ksgPwG+qFXfLLTsI
         VBRVrhD4fmib1whZGzuleMHIlSlxPP6zk/EEDureVqrT1rkr7/K1EF7yzf8ukQvkWZQ2
         NySQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PR26OryL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700126469; x=1700731269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cs7Ph4SuzNF9wHTfWlbPzBPkL4m5xkHnhpgTuJ/pVjo=;
        b=TAwF0fb+SmdDCZahiSMSs04pjWRpkVTg4Ta0T5fF9iJQEW83M3ffnFdK9qkT0FiH4c
         izBzmnnN6mJNlqDlJMQaUW8YogaSYsD+AiFFaMy/3vCVmG5Hq0d/iGDQNjPsan7dX2vS
         VwfmLDek0WeIHQsXo1gLkVjuiwQI/Pa/JaBoEv6cIpJUb807xje3bGGaUeNfAxfZCjbI
         eqi/seXabF4z1QPEij+1RZ6eu4smb8jYrgXddtCD0URb+7NdYqlD1rdOhkkwIYJIrByH
         lPpJyhWX+hXEwMDyNkFZrnPQB0V8iw7z13cWQ8ss374haLOmT2pfGViQtDGAQRScP09H
         7A/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700126469; x=1700731269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cs7Ph4SuzNF9wHTfWlbPzBPkL4m5xkHnhpgTuJ/pVjo=;
        b=bDRgCHuUcWyMl381zQYLPYyNWv+JoAgbyI4zMwVWHs4/Gm89U+76riwXNNk64gMIOV
         DuA6xswU8aZlKa9q8z87S+bPzrJ0EB2V7eApkvOv+0JmIDoKfJu9lqt6McrEJ5lPZLCh
         qxPEMVe0VziGhhp6/oq4td8dP2BfLzAOUy1VNj4HTAUu9T3uFFg/BKOI39J743Z8WQEW
         0QV1aHR7OfDn8UGH8FSEx3RkF9lR+5zSVbLqhO9Y2DN26qp17gm/OajUaDONBtsxwAwH
         YczKjz40/5Cx+ZZ281i2jyi1kWEyvi7PAmaNfeKCGNLRguRLSlge2+G3lDc3GQC7JRym
         47/w==
X-Gm-Message-State: AOJu0YyWrIo9jqzH0sAPU1mintfaTSGzdXhuF7gUd868t1/RbgK/fMTd
	L3eXIxeEChZWoTJTgbMIcqs=
X-Google-Smtp-Source: AGHT+IE5PLFFae8ypWhkjs17jFKihHulwKFTGaFYPatRTcBxsxhXKnoz8aQBYKvplpnAD3UrlZgcsg==
X-Received: by 2002:ac8:5708:0:b0:417:b901:98ff with SMTP id 8-20020ac85708000000b00417b90198ffmr7979379qtw.54.1700126469534;
        Thu, 16 Nov 2023 01:21:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5847:0:b0:41c:c119:24dd with SMTP id h7-20020ac85847000000b0041cc11924ddls741231qth.0.-pod-prod-07-us;
 Thu, 16 Nov 2023 01:21:08 -0800 (PST)
X-Received: by 2002:ac8:59c6:0:b0:417:d340:c426 with SMTP id f6-20020ac859c6000000b00417d340c426mr9515917qtf.9.1700126468176;
        Thu, 16 Nov 2023 01:21:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700126468; cv=none;
        d=google.com; s=arc-20160816;
        b=Q6fwcfKxHFmwxTdNJoFJPJ0KHZSjsw61Tn1ozPvhWsv2X7nSX878yadBMOvyhAyLMx
         JqtwqztSmBiZhMIfFP3qoihPWiqjFAwU8xRfoUl8q27F0idItM78Lqyux+YRe4ytlU1N
         Z/WGVAW9WVwwZlWCEk+maOHj0lm81kvBooa8kMAu5s8QKJLHyxdvHM1E0qlMeqzVltzh
         vyKRo3rksO6K0c6d/uKZRka/0jGy1gGyKXLLTVdNqoERIfK36i31smR4ipcGwkw2d3Ey
         o5qZ16QtQnGDPgzDF3hu2X4Ih3j5UITZIoDFQwomAc4q//krVoBZi1XTX+0r9bTXg1xc
         kPkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hL39H6t6bxsTD+ztOctS1932vRb+QRkl89FhLK7eO2w=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=FIDuDj3wZTpKw83Umykl0BIP6eswIJi8IS9lCxjgJesAZ08fco92So6X1ygEgU1gAM
         xR04eb57ZI3Jta0gr3H/W5g14SSp6LCDKJfV9ISH0kq09WbuVNUSy4F8NZSLPc6pDM3j
         SiFhxpE64eaNPfsrLoPLgJzRkb5AcihayGP8WHBfv1nXobiDh05ytZXAOl6y0vnnB0tp
         U8m/DVy3oyLeA6PqESKY6AccgfdgszprGYjqjxGCIkJpQoOugfr6TO+zQzHuhUQvdmvB
         XmF26/K4Ofcg+naBsl9aEfqXEh3AQwlFelGra3NaGzxX/te8X8WqLYbmJOmKfYNgrKms
         1k4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=PR26OryL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id ge24-20020a05622a5c9800b00417048548c7si1882584qtb.2.2023.11.16.01.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:21:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-66cfd874520so2971356d6.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:21:08 -0800 (PST)
X-Received: by 2002:ad4:5cc6:0:b0:66d:15de:329c with SMTP id
 iu6-20020ad45cc6000000b0066d15de329cmr11619912qvb.43.1700126467765; Thu, 16
 Nov 2023 01:21:07 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-21-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-21-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:20:31 +0100
Message-ID: <CAG_fn=UhFURUGqFXCrWym98PLzSR9oYfVDFvLpoaRO91_CMenw@mail.gmail.com>
Subject: Re: [PATCH 20/32] s390: Turn off KMSAN for boot, vdso and purgatory
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=PR26OryL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> All other sanitizers are disabled for these components as well.
>
> Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
(see a nit below)

> ---
>  arch/s390/boot/Makefile          | 1 +
>  arch/s390/kernel/vdso32/Makefile | 1 +
>  arch/s390/kernel/vdso64/Makefile | 1 +
>  arch/s390/purgatory/Makefile     | 1 +
>  4 files changed, 4 insertions(+)
>
> diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
> index c7c81e5f9218..5a05c927f703 100644
> --- a/arch/s390/boot/Makefile
> +++ b/arch/s390/boot/Makefile
> @@ -8,6 +8,7 @@ GCOV_PROFILE :=3D n
>  UBSAN_SANITIZE :=3D n
>  KASAN_SANITIZE :=3D n
>  KCSAN_SANITIZE :=3D n
> +KMSAN_SANITIZE :=3D n

Nit: I think having even a one-line comment before this block
(something similar to
https://elixir.bootlin.com/linux/latest/source/arch/x86/boot/Makefile#L12)
will make it more clear.

But given that the comment wasn't there before, leaving this up to you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUhFURUGqFXCrWym98PLzSR9oYfVDFvLpoaRO91_CMenw%40mail.gmai=
l.com.
