Return-Path: <kasan-dev+bncBD6ZP2WSRIFRB747YGNAMGQEBOYZCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 096A7605060
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 21:29:04 +0200 (CEST)
Received: by mail-ej1-x637.google.com with SMTP id sa6-20020a1709076d0600b0078d84ed54b9sf8556791ejc.18
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 12:29:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666207743; cv=pass;
        d=google.com; s=arc-20160816;
        b=L0Fc0986/r0ygovQELbU6C8Bmh4RxrXfLG78M6QY3/YlDeDoXtz+HPg8FvreW2jaX3
         MjzwWq96AITyx5flAGDWrx9zbtqyd0rT0M6I1Dn34OSKIoSr2wcTu3Inr8CU1YzwgOYe
         krsHY7JUEl5l/WUfTw+S2yRf7WElDXuOD48La8FOfE5Ge5NgFInQZIUSiKROL1oznrJ0
         DBIxgDEvuQX6C2KzavlwIMHZL1j9i+l0gq+dv9u77GnkPM7O4KkD+lZ2eivEd+SXcIf0
         S+WhPKLtY46T0XacD45vBILCFh2VqTPBwBAiN9HP88ljF8XR72Sv1zZf/FCVQkgo9zZc
         QNJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:references:in-reply-to:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=J7Dm8XZsn/fSKyy5BOBYcMcZtj92wqnIqY4IzXePdBA=;
        b=VCH9Xjcu/2wWYW7x9neS6Rah8NiQUo9zSjjzafU5XQ0ZKt8gguqpYk76pTQ882w8BM
         gIWVir9NLHFyK72Z38AVSN5cjZwudWE9KQe7la7YjsnlHVDzuMzzjhq47AELci4KREUZ
         Lv/FsrDFDNqy0i62Jp4RFKVaJuYfU2nR4T9YKp7ICEX72AKgPSyRNRJ9Nm0/AcUGj61M
         /83wkiUDFwE0Jy2wIWhilas0JN5/riMjk+tkbgUKdmMw0G4cexSbvUKTL0uowHpPUzoG
         lQFBm8bclot00xy8M/f08683daKgRpfKYO/ATPHofIKx2IP0E8mbUxQG/SERJ6oenK9M
         SCGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Zs3D8ie/";
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=J7Dm8XZsn/fSKyy5BOBYcMcZtj92wqnIqY4IzXePdBA=;
        b=pbYot+vp3a/VqIsybpm6pimuYo+Ajzy4XR5LYwE8L53xgK6n7VQzj9CwABTHm8+ND2
         DfJC3msjxc8DX9MBOeOjiyYCC5xcTllhtyzaLbHvNad5WQ0VagvCxdDjwBzN66Z+PakH
         EpxE0EaO1QbomBftNRXp1s8KpqJDuNfxayMg18qh4IzYv1RmSW4sV45tZXbuyX2VA5DB
         KU3XPRvKbrrVYR3FI5YLmBjlaTVfwTJuIXgfJqCRYbAKynofbV2dAqfnd00Zbbdzna0o
         Er54vOfIzyFvkrR5qQS/La+6cJuk2hc6pY5GYDzmM2Jrtm+bwCIP/gxBNwaKP9o7T3Yo
         3ujA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J7Dm8XZsn/fSKyy5BOBYcMcZtj92wqnIqY4IzXePdBA=;
        b=Us78eRJzpAp1w783WFDxHS49gJpuE+lwhDaMJSfar1Y9gUTy4J0g3olSNKvLt/ZvZN
         bOsu3FpA7xCBbrc/k+bQtBNfR94DRupAZK0oYXpo7322u+LekmdIwxrj/u1lntVL98Ka
         WejMgZSQlvQ2D5SNxM2V4AVkyunr/1+XWnRkH7agtmabEyWn9sIjXGhUp0UEuLtAYWet
         B1pzFumhEVB1k1Z1f2/VV06npbYiHypaXQ0yNq6ukyH8B2A1y8QA1AhA+rUSP4zAQXwE
         hoNnMZuUkqBMBFI472y5e7W4Jr466YJf9RGg0ZuT7hdwC21bLmzT953ozxkkgYHnt4M+
         Q3YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=J7Dm8XZsn/fSKyy5BOBYcMcZtj92wqnIqY4IzXePdBA=;
        b=0d6dA3cJlLczQvgC/b/Est4T/wc1CqxT5FG+6i73BKpvVZUBDEd60CZUdSI8s9azLP
         A0iXqafkGVQ3/oR41xVVapLqIsULxXL5ceLwBBZEntWGdmwMO8LEZvQwfEnum2xDMdTo
         i/BXEJXHlWeVXHM/9j9v/0wd0VMkkduai7DGAFgSbQfYthGNc6S3PEsxfJBWTadv77/s
         NN1oCL2dOYu3nlShcEHVQEAtBq0JrV2aq4zDt47vOUUtDDcbv4GbHY2AKbHtbKZBbarc
         P6bLRgsjcPYcnv4nM1af9qvhTMX2eiutlycazanSpGIIPFbvP2p8heMZ+ebqsv7seSfl
         svlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf05Evn+AauJGFUI1JoI2mc1ViCyTkRdIFxTziIIFjzKMOgjf//3
	9KhomBILUagQp96/A+XPTcY=
X-Google-Smtp-Source: AMsMyM5xB2nF4lm7ww9o8nEqEwEGzD80WtcjmScwPupQk3WOiLUK8JxulD3GUfOJf9WLZioC8bcrLA==
X-Received: by 2002:a05:6402:4511:b0:45c:b2b4:3e69 with SMTP id ez17-20020a056402451100b0045cb2b43e69mr8803550edb.339.1666207743495;
        Wed, 19 Oct 2022 12:29:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:681:b0:789:e735:3ffd with SMTP id
 u1-20020a170906068100b00789e7353ffdls9947959ejb.2.-pod-prod-gmail; Wed, 19
 Oct 2022 12:29:02 -0700 (PDT)
X-Received: by 2002:a17:907:9625:b0:78d:bb06:9072 with SMTP id gb37-20020a170907962500b0078dbb069072mr8107513ejc.472.1666207742508;
        Wed, 19 Oct 2022 12:29:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666207742; cv=none;
        d=google.com; s=arc-20160816;
        b=O3LWRs4KBhDrA7N+kNGjYFSNHKPdewXbRKVAu/x5Nvs4KPOM/bLaggMowoBelUoZvq
         ZOwmrIO+eKg9BHO0joKet6ft41mLyZb51Cu9UEYvzA6urlRbIilqmyZlqHwvzy4SBvd1
         A/X1mXmbHyf5OpgfAo+Bf8cYfpS7kYIEcOPX4Q+ROGAasiSnE3FZQW4BQlfTfQZur0BR
         fsNA91ln17uM6flSehyTZSUNX+qAi17fv8R1pZnBOztJlpUOZ3zUkpVfMKMPM8r7m3iv
         p0Q331nGSA+AtZ0+YC503PolbKvZsVR3h+dCHE6heW4wlDKkDPG+5exh0gIEdr+C9mj5
         pb5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:dkim-signature;
        bh=1J+LkGJJsG58CkJ3Qd9XTdOjWMcQXIZDNg+2efZ9DT8=;
        b=Rlo0gOvZf7Ykuve7vO99Ck9if5GV7Z+VjZDPYOTdL/W2l/IQvNOYL/ZS5R79xIzSYA
         kequTKo7DZ4RXRMY4jtnIpQxRbaq7VnT0J5Z8T2LcUcbUM5s6b8COiDUFZlcRviZT3L8
         ul/u4a3iCpTVURgWnBLs4t05vaTZbAJivtGs/03k/frUu6fYcemj2kwkz1Vu+ajOUDOE
         XmmRSnvT+uao3lPg7LdolcE5Ix/gazEAcfTHhIL3Gxx3x4WyqmcfDLGvZDt3adXGZ35b
         YqLq0GEIF43Mw5wUpjmANnfB6pKqEvdb7NsD2zqoFEpBpv5g44kK0Gfv9C9yGu3AqEKa
         jlBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Zs3D8ie/";
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id u17-20020aa7d551000000b0045a1a4ee8d3si652917edr.0.2022.10.19.12.29.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 12:29:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id b18so23465531ljr.13
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 12:29:02 -0700 (PDT)
X-Received: by 2002:a2e:8796:0:b0:26e:8b13:a29c with SMTP id
 n22-20020a2e8796000000b0026e8b13a29cmr3457109lji.210.1666207742198; Wed, 19
 Oct 2022 12:29:02 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Wed, 19 Oct 2022
 12:29:01 -0700 (PDT)
In-Reply-To: <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com> <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Thu, 20 Oct 2022 03:29:01 +0800
Message-ID: <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Zs3D8ie/";       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

arch x86, this's my revert,
https://github.com/youling257/android-mainline/commit/401cbfa61cbfc20c87a5b=
e8e2dda68ac5702389f
i tried different revert, have to remove kmsan_copy_to_user.

2022-10-20 1:58 GMT+08:00, Marco Elver <elver@google.com>:
> On Wed, 19 Oct 2022 at 10:37, youling 257 <youling257@gmail.com> wrote:
>>
>>
>>
>> ---------- Forwarded message ---------
>> =E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=9A youling257 <youling257@gmail.com>
>> Date: 2022=E5=B9=B410=E6=9C=8820=E6=97=A5=E5=91=A8=E5=9B=9B =E4=B8=8A=E5=
=8D=881:36
>> Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
>> To: <glider@google.com>
>> Cc: <youling257@gmail.com>
>>
>>
>> i using linux kernel 6.1rc1 on android, i use gcc12 build kernel 6.1 for
>> android, CONFIG_KMSAN is not set.
>> "instrumented.h: add KMSAN support" cause android bluetooth high CPU
>> usage.
>> git bisect linux kernel 6.1rc1, "instrumented.h: add KMSAN support" is a
>> bad commit for my android.
>>
>> this is my kernel 6.1,  revert include/linux/instrumented.h fix high cpu
>> usage problem.
>> https://github.com/youling257/android-mainline/commits/6.1
>
> What arch?
> If x86, can you try to revert only the change to
> instrument_get_user()? (I wonder if the u64 conversion is causing
> issues.)
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht%2BTCg1Q%40mail.gmai=
l.com.
