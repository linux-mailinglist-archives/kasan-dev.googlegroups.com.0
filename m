Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI6R3OVQMGQEALXLYYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 543A180C703
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 11:47:01 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35d4871f67dsf46520145ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 02:47:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702291620; cv=pass;
        d=google.com; s=arc-20160816;
        b=vyNJPcnZcS1uGAlXh/0dAzLhFdj1+kJqbxVMrfh0BaQzkyj6CJjakv9GWnPX+6nJoV
         1N8mU2+gUhyQf+Rl4s9FHH8iO+CjimJMTxdwZYJDK0fXAqlDH+T+47laodCLQtpMJXNw
         bLrnOAA+ywP6efDac6Jzp/o982lehCUNn0wdl55Z0t2P1ciWN7H0hr6PpyzWKQTfPUb0
         QAY3Xo0QM5QW8F3ouQofZP+9GEJGZaN+YaRLMifKfXdi4PYeG33tURNZsvufBU48e4Lh
         8lgx/ozT606AG5Cx5/nOJUUQ+asRQJrKVtDoAPqjc8Mrmq68v2y1nyPpVR4B2+q6Y1Ip
         2Y/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5vXLumpJE2m0LfpX+f59xH9Y1pPP7BHWLim/p7ORPqY=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=o4vKY9nOyx5t73GmcioitXxWKJtIHfWZ8f83+MFbPXyVYy/0yv7nrb8vkARbHwlxjD
         RPEJLh6X86/nwCBT/PBr0ZVpsvomRwTwo0optVZlQt4wbvZKdBSTpiB0LOVOxDWMolTD
         0B8wykcmk2x+f02jkTc8JNYpp5NLCjguEaS4VsIQRmLBWNsJhpqrCk0lN98KPSMbtUyJ
         ssrkoYRYHTN3aSuO8lKIaHsJqzdOnBTqPkZLcbGYDBGEsuSC8g1KaZ84xOr1LNNuZxtb
         XaCpIDTd8L8h0Drm7NYTSxN8UfWCd+xiTAv8/fG5FL1tiAiNv6t+9Q/rFm98I2GoH486
         73eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kOz5AhO7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702291620; x=1702896420; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5vXLumpJE2m0LfpX+f59xH9Y1pPP7BHWLim/p7ORPqY=;
        b=OiT4VuXp5dfcYlV6zEYbxjSz4M2HNgxQtIx/F9n7wFTCdGcapIFfGNFQVhJjauj8bb
         5VyZoGpDDW5wMG5j4s69mmLi6tar/cNFcitXqe/ijXjvTfot/MFr+Tut38YyR1y8F+16
         EeXRRltFshW8aGikrGZU7eqRqktxvb+/W/E2dcLYpEo0EF0trxdN1xgEmi/H209WEvsm
         zKl/cmyc8dT9pJdj9Evu+S0bU/DBBUraovPG9XJRT46Fa0IqlLy3Sj4X8hTRJ1665qrm
         qzh6qpGSzAO9zLTp8aKJuh/dMwrFhTvnQuWqeqmRNEViO648rjQUj1jzyaXOO6AqT5rm
         Witg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702291620; x=1702896420;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5vXLumpJE2m0LfpX+f59xH9Y1pPP7BHWLim/p7ORPqY=;
        b=NBKXswGXN6eWlCebZ+XyNeed+Ta2mEOYfn2Gz8mNLjJVA5dsvvoirpWUkKXVeZUAtq
         Z5WfxEkju+IWFGt5nq3yObtSZfGIQ+lCxlyChcDFrTuMdnBwOaUHhJ9Fy2XlD9Cgvpq6
         8ivjw6RwFCrvfTFyrlRBMQXK6Hcbz8zSY7q+etoAdQYZARVJSnU9TGv/leRQ2YUf6/nk
         noQF7XGCsy1uwfJZsP8K/GXyeHTXBZsVIsgW+MNQ4KuzziAy0YO5YzcLLRlm5CqqJXLi
         IbZTjO3WZ7RYmTbSQoKN6rgXuaR5jUasWSskkRdfZncDad8XCNZBTZotjtrxyfrhaJj8
         iBjw==
X-Gm-Message-State: AOJu0YxFMdV7EvjcEGUrWZ7juWAXWnXU0UI+QTcHUKHrT+7tSeEf/p6U
	4WRUMXULMozGCBYEvyT2QNg=
X-Google-Smtp-Source: AGHT+IHHcmaZ/AF1nIyQ41nDud13YopGJ0UyryDoIU92vNjyg+r2RbnZlEY0ZFfieG7Emw/sC2fXGg==
X-Received: by 2002:a05:6e02:190c:b0:35d:59a2:929e with SMTP id w12-20020a056e02190c00b0035d59a2929emr5051135ilu.50.1702291619993;
        Mon, 11 Dec 2023 02:46:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:18c6:b0:35c:c82c:c797 with SMTP id
 s6-20020a056e0218c600b0035cc82cc797ls113153ilu.0.-pod-prod-08-us; Mon, 11 Dec
 2023 02:46:59 -0800 (PST)
X-Received: by 2002:a92:d088:0:b0:35d:59a2:92aa with SMTP id h8-20020a92d088000000b0035d59a292aamr3915250ilh.62.1702291619345;
        Mon, 11 Dec 2023 02:46:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702291619; cv=none;
        d=google.com; s=arc-20160816;
        b=h5gVZYvudMLHqFMZ1U8eAR+3JKlvRNkK7FU0fBvhhc+v2G4kxCRbtx653ywx3p60S4
         lbaA3O+8zpcT+t25g/BgJPwkSPuvxBl+cArKALWrU8QGMEUYUjbn3YJuys3cRtOkD1Ib
         7P9UACUP9SgiyCQFQZoHOSlOnbgq9XhGJtu8uI4TWfafgDaG8e0gtRLHbPKC6kND+t5U
         OcnPtDYs393S17jZOy5mbCMGetWVtOUwtMicnHClR9r1eaknXX3ionM3RQNlFOIHKrf8
         GQOXOk5omvuH5TOmYF6saHC2KwSJb9Q/fAYdGAOpmwUAZ2u9nCYB6sfXq4v4FOu9nu2/
         RDzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dbONbDTwPKE3MiL/eslKI++k2YglZ6miec7hwk3eDBk=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=R7drWgn+JPKc14Y0I8sXMWM9y0ZeirInJ6tlnK96GVKeSepITrXc7q6FCPloZLtdoX
         x0TnmCdIQYLxzGyli7V3YONL2tT24fIi6fOhmazrOXU8UuQofkSV1j41EofmfwRIaf01
         jFEzbUUKkEZ9kXvtUt6WoclZlMawRY8AasfbVYGDxy7QT9DGA81IEk6XcXZehXhCwGqz
         aWchJ/ewAGLllu0aW6ER1e/5MvQhNBo2OIXdTdBZEzc/cXpnBH3T1NyI9UM7LoBXp9Gj
         0I83agAowQ3lRwGt9TTjF5s4Pk/l1jU8bLrcxe0BxY8cKxeAMX6qnDRyslMhg+jCgyQ6
         MO5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kOz5AhO7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id a11-20020a02910b000000b00469321f5169si471532jag.7.2023.12.11.02.46.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 02:46:59 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-67a8fb9d112so17430846d6.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 02:46:59 -0800 (PST)
X-Received: by 2002:a05:6214:20ee:b0:67a:d8ce:8e88 with SMTP id
 14-20020a05621420ee00b0067ad8ce8e88mr3089154qvk.110.1702291618597; Mon, 11
 Dec 2023 02:46:58 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-31-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-31-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 11:46:22 +0100
Message-ID: <CAG_fn=XyTZHU45EhinUSm-+Thux4VPCpT-jyf=cP7hNPcTbK8g@mail.gmail.com>
Subject: Re: [PATCH v2 30/33] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
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
 header.i=@google.com header.s=20230601 header.b=kOz5AhO7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
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

On Tue, Nov 21, 2023 at 11:03=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> put_user() uses inline assembly with precise constraints, so Clang is
> in principle capable of instrumenting it automatically. Unfortunately,
> one of the constraints contains a dereferenced user pointer, and Clang
> does not currently distinguish user and kernel pointers. Therefore
> KMSAN attempts to access shadow for user pointers, which is not a right
> thing to do.
>
> An obvious fix to add __no_sanitize_memory to __put_user_fn() does not
> work, since it's __always_inline. And __always_inline cannot be removed
> due to the __put_user_bad() trick.
>
> A different obvious fix of using the "a" instead of the "+Q" constraint
> degrades the code quality, which is very important here, since it's a
> hot path.
>
> Instead, repurpose the __put_user_asm() macro to define
> __put_user_{char,short,int,long}_noinstr() functions and mark them with
> __no_sanitize_memory. For the non-KMSAN builds make them
> __always_inline in order to keep the generated code quality. Also
> define __put_user_{char,short,int,long}() functions, which call the
> aforementioned ones and which *are* instrumented, because they call
> KMSAN hooks, which may be implemented as macros.
>
> The same applies to get_user() as well.
>
> Acked-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>

I think this patch makes sense, but I don't feel myself qualified
enough to stamp it. Hope Heiko's ack is enough.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXyTZHU45EhinUSm-%2BThux4VPCpT-jyf%3DcP7hNPcTbK8g%40mail.=
gmail.com.
