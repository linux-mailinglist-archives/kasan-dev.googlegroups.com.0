Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWMBR7DAMGQETJLMMLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 00D0DB54318
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 08:42:35 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-7671821d5a7sf22790566d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 23:42:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757659353; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uo1pKtYtzlrAPpXzPd9askXwGjb2f29kfP7HET8lPFD1GzEyhBY4FEcden8aDJkh1Q
         Hzgjkx8UawW+cLPM9qE7Gl3uXVpZqmHD++4OcGWpdJv2qy3Eo/+2HcM81oc7URb8HBNG
         GH1k7xnStzDUPiwZ9w0ydDjWEhOYG8yPbiq+R2Nh5WqJnu2yRZXH1zMkh9kh/vuXH4y4
         1gNzsPHmw4QOb/6sXRE7nHri7n9VvLvGZv3CrT0a4MB9t+555FiMrjGUF490cysIt3a4
         pl5TZjhl8rhq/NUyMfWcMAufTWloA5SVvZraPblOHfbaD8/gjXWd7t3pixWX419Dw5IY
         la9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8FEVX2hj5g1V6Ufr3fXAw6LNO7wD0M3fBjMF3vJzkx0=;
        fh=IX5sXUmCLzQKrHvofm3XU11u+3NGo31ohkDfAdN6Lsc=;
        b=ZR+e74BfWEDAbEd4cKds67owW4AOtym2HunpAecGx8BOaaYaXXEbxbvYX3oZp1UYmk
         DbGObJIzFEKSm5A2BGqaOBM3I2ZZC72xPiqp2uAA7lUf6GHyc83N2HaY7uTstneX910s
         ed44n4O5mIM6YD+NfKdx7OEqjX+slyjVjsuAzI3iG+7pwchap2flLzbYTxrVhAh9spik
         nYl5eteOZd0saCik7DvntY8VXuztFFPDIFm5KH36qSuvphahMkG1MTuPEyQgJe8PpZ0T
         X+y+x7AQnsruAvgGWUXGiP1rhCdPHAPK8kjHBeMqxdaDPcBLG6ya2bUE2jdpI9JO5qI/
         AT1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f5NxMfJB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757659353; x=1758264153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8FEVX2hj5g1V6Ufr3fXAw6LNO7wD0M3fBjMF3vJzkx0=;
        b=ATbmlGvrSkaah638wHj5iJswDl76g0W7FVZC6UW2srVQ7yCFvU/Ox7Od1lgeLNveCG
         APgZS4cjlfy9b4pB3LXl9Qo8zvuPHOtwljWwdBXOQm+NUkAvYZz3j7/O07xOOgCw+EM1
         8Wzb/66b2i/xIwa0e+59QEsrChv0aShpluNbri2HbWqqCWPcX1lOVs1gDNb+HTBwmU9i
         axqO6+V4h0BHmTZ6ToXogqtOwi3Bvg645D3sYRJJsRJN8OKHga6orJn/sxHeIJpC5Qe1
         FBoynDp6kQ1u9lBMqiiKzKLpPJOACQgMOb5ajbifF0CHIuY/I+8vbLvVUFz+kyGQ51Us
         1nnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757659353; x=1758264153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8FEVX2hj5g1V6Ufr3fXAw6LNO7wD0M3fBjMF3vJzkx0=;
        b=TBf12rZW15DgLPOH3t9fznJ+rShZMkHrsWzlUblL9ImYLHLsnPtsDbP/3Cq/RZ0ryp
         nHLjvYmjd+JSjoLxJs01wWv5sr0JMKKv79EMZSLQiQc8trc7xluR5g1hORqUoXqX2s3J
         2HdBU5pcuAoK4ZAKsBsZ+FbZWUwOV3GFQzXpv8wAjY50UX367eajFtYnFCIOY2IQuPvU
         +C4SxVCvumZ2uxmiTh3HVaA7xcOPtYLj2R0RU08Cnr0epq4zKVJ2eDkW963lmGFeMKcn
         sPKfmSPnPVjPBcelkZtEhyBgG/WH9/HLMerxrksi66CvgCoO9q+DR7DTrzVwGeKbJnd+
         JzBg==
X-Forwarded-Encrypted: i=2; AJvYcCWM1YmD+5d5eL828K27LcOSQJegEvvhlTgy4r4+OdBZcU38TmpHlAML48lqMVoYcJI5xXhxjA==@lfdr.de
X-Gm-Message-State: AOJu0YytmYBOg+19heX9rNxuTTe2vXg/A3tI5r2AWZE199XKwmQpm6li
	n5idjAtlDa7SLQJ+jRiJzw0tFMgWGl+0z2g8SVE9d642tQvl8qUOrGzP
X-Google-Smtp-Source: AGHT+IE5wSXGS53zfTs+Jz9GhzsyFSVjnz2SoyzEbzrD45SEJuZDNB/8TSJlXcNNeTMdlm2B/k1EUQ==
X-Received: by 2002:ad4:5c6d:0:b0:72a:c6e:c716 with SMTP id 6a1803df08f44-767c49ad8a1mr29820526d6.31.1757659353398;
        Thu, 11 Sep 2025 23:42:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6jweVjJ8LB9+dJC1GYi9qH8cWOYSeqP2OklsYDy4o0pQ==
Received: by 2002:a05:6214:20cf:b0:70d:ac70:48d7 with SMTP id
 6a1803df08f44-762e46c43fels28678686d6.1.-pod-prod-06-us; Thu, 11 Sep 2025
 23:42:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYliQPIWytUUue2WeVFP4t30RjWf1jQlqmd1L8aVsDKca8yvTQSXMMbuJKR37L6M5lcJ9mDq7LfWA=@googlegroups.com
X-Received: by 2002:a05:6102:3709:b0:523:e248:c315 with SMTP id ada2fe7eead31-5560a2fc296mr696342137.13.1757659352500;
        Thu, 11 Sep 2025 23:42:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757659352; cv=none;
        d=google.com; s=arc-20240605;
        b=Xonqd4L2yDVkTNutRkdvRN3dneD4sqo/aaoOGgRgvFztYjdfxTMsXzIIYoLS0CQWVN
         EawbDJY2OyZ38eP21/KJBnW+eDc7O4l3hSTPhIrhMYW4PLTmuo4HZI4WlvAysrHkxDQ9
         qVA5pDLG0Su6815GaxY8dZ8qeiWfIv8xCQG3nLboUk5x5R6uELl4PQrIKKBJ7i+AANNC
         NXmFbPKo2vfu9492Ja5bU7kFTIeWTBTSo/PJwvwHWQa5rWBFu8RukKOCjZyV7WL0l7rY
         wPwfwEiF1a6nzejx39meKe3XCEV3O2yQAo2cBQ3FfyG9FXQVhwp7WByhmb5Mz59un74Q
         +R6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NiDw3YhiRCuiqX3s8Sx2YRwxOWOYND2WGqxePm5DDYE=;
        fh=CoTGIYlm1nRrcIB8UA39Ua7LFs6sm+P8MupX1SwsHIM=;
        b=GRXewDrbLPVXoI7ZmQrVYkjjtxU7RFw+kabNlEzY6afTV87smkcT/ETgEBzya5W2I+
         iOHT66ri4SVRfzolD4+I0ESCNqZN1fVT63JtC9xSrU8yTSEe8zX3Lf5mE1k5J8Guc9c9
         SlpqZaaUC8JgeB90Eh08x6H6x2wtH9zAC0YstUvG0W8+SGOKywUDU1BJUMRfQdyJ1kPY
         uPaGNyow/ddtYso92t0d8scaPrgW/MAHB4mycbBKO7ryJIAO01VcdaqsYexKFGHkzsK4
         cZngYIBwMMWopjXg8LK/udUM37ucE84/kdh5XR32/BmGNtdJ+zZ3jH0B2nn4uoKBt5hM
         bfvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f5NxMfJB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8d09bfb355esi63407241.2.2025.09.11.23.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Sep 2025 23:42:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-7639af4c4acso15797416d6.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Sep 2025 23:42:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPiAFK+Z9vHFa4nkorsHL/UqyNWmqQh3+LaGFBJHJ0j/nHUoWfr+6NLar3EwF7slSho6L/VDoj7Lg=@googlegroups.com
X-Gm-Gg: ASbGncsp1PNLCn3D+DKIIJpKqpNitW1FIGMowQ5h+04LADvFNVufjbnPaaCFZDd+cjm
	V12iVSUeKPG1La1PJtVc306SM5CMx6AQhjK/dn8aJeR8USkdY45lpVCKjqJyjNSjDtM6jnCBiDS
	vFRUJ+X9CuHILQkhFWV4hXAO7RSsJTHNHbAlfSmSbEkl3M4vNQ8Ckf11p0wDrC/VB+Y9NToXy6S
	D0vQ7GzQmEJdoSdfzn3jSr1g32I3WTLrlXb/XWHD2YYj4ZN6DqE//IzLoYzAMVyuw==
X-Received: by 2002:a05:6214:410d:b0:742:1ea2:b5fa with SMTP id
 6a1803df08f44-767beaa719cmr24286056d6.27.1757659351417; Thu, 11 Sep 2025
 23:42:31 -0700 (PDT)
MIME-Version: 1.0
References: <20250910052335.1151048-1-wangjinchao600@gmail.com> <aMO07xMDpDdDc1zm@mdev>
In-Reply-To: <aMO07xMDpDdDc1zm@mdev>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Sep 2025 08:41:54 +0200
X-Gm-Features: AS18NWC5FlcfxTDi4nqpRg0jzSdo_HN5yk0SuuDRYsNBfDIot3LDMm7TkcnabIg
Message-ID: <CAG_fn=V5LUhQQeCo9cNBKX1ys3OivB49TuSeWoPN-MPT=YTG6g@mail.gmail.com>
Subject: Re: [PATCH v3 00/19] mm/ksw: Introduce real-time Kernel Stack Watch
 debugging tool
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, 
	"Naveen N . Rao" <naveen@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	"David S. Miller" <davem@davemloft.net>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Ingo Molnar <mingo@redhat.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Namhyung Kim <namhyung@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Ian Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>, 
	"Liang, Kan" <kan.liang@linux.intel.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-mm@kvack.org, linux-trace-kernel@vger.kernel.org, 
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=f5NxMfJB;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 12, 2025 at 7:51=E2=80=AFAM Jinchao Wang <wangjinchao600@gmail.=
com> wrote:
>
> FYI: The current patchset contains lockdep issues due to the kprobe handl=
er
> running in NMI context. Please do not spend time reviewing this version.
> Thanks.
> --
> Jinchao

Hi Jinchao,

In the next version, could you please elaborate more on the user
workflow of this tool?
It occurs to me that in order to detect the corruption the user has to
know precisely in which function the corruption is happening, which is
usually the hardest part.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DV5LUhQQeCo9cNBKX1ys3OivB49TuSeWoPN-MPT%3DYTG6g%40mail.gmail.com.
