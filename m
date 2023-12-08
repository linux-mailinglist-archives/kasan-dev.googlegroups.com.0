Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3F5ZSVQMGQEPQGM6UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A611F80A4B4
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 14:49:33 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-67aa6e60d0dsf23193506d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 05:49:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702043372; cv=pass;
        d=google.com; s=arc-20160816;
        b=PzOGrJFDisUAVeMUvjNM6MVBCasQystWoYt0QQBTBBSHJrIJiH+QTgjEFZD2pSr7EH
         guGnUU8as/Bb5zii3ZV/GEmqiQIO/mbzHcUHs8eMY3yT+eU5/+H71oGv3OuNqoDWeXiQ
         b+NuOat1r9V+3fDdO7AEHzksy7jwCYzQ2USJEh8kmV87+87tLQVuXHDr4yt1k1B85Hit
         1CZtjvL0zem4/cXt8rFc+CLnuV8wB9hproC9LwyXRhZHozujlRTTrBSq6TaYkU8HfmQj
         CeKApWiAzOjPAhmhK5lAz6v5SFCJtyTH1U4FEBZnwYAiqomjItbaTcO7u2eQMhmO8PwY
         P8+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qVfgea+2XXEWysBpQagPlt1NRhvP2C/6jsBi1mtm4e8=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=G4sTJX0fVMETPZeGkR0r6vsLIv3JbfpebWCLP0Jit7wNXthGSXWCYOCX9IVbztwJXN
         Sq9sOFYbBWZAiQhrF7LKasHEiZ1cTgZqOYHqbkzEFbcdvlzHgI4/ANCjGUT07w+e8fvK
         ZdtKbkcEYu7V2kQ7VSTjMUBEpiZ23pN8wxD/TdSDUMR336E6LYYYzHctg/edOf/LqNzd
         lLxnyyl7zA5HIaM6cypWK4R/YtWetTrSigF/rT6agNpAIhDshyVQKQVviL8CjnMxYbqv
         9XzSqYNPtVmfeJrZBq7kp3WFr3MPb27Cdlb4Jyh2G1PJE2d6as/c86boDvnpX5ht1U9M
         lm2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiUpsH9a;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702043372; x=1702648172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qVfgea+2XXEWysBpQagPlt1NRhvP2C/6jsBi1mtm4e8=;
        b=hHwlAdtQoddKKUt/s8KXoPW4eF49tFicusrgLJt0N+ok9UuSdqMZ9iiMaZn0EiYqSG
         h4b1IzXHEeE5ucM1tjEt5cJ6xTEZ5Rx1QrukmPTekeGnVSSTDeiNhRBr/EtDl8vwkEq2
         buIeO4Avb83XbpIkotzcuc02tFU8rGKAyVDEkmHF8oYOzJ92wdtWTfSb/3eiQjUryIsB
         H0Zmi9mIS3r8hC4Yqpj1AOFkAUeY4TM0sfsa+h16GR38HjhJcDcfEEcPdxxMRt8KX/yV
         PeHBnTwS5bMOUjyPvla5TvFkBo79nTtKuiK+BSAsIs416oeEY1U0bJosRGWcT//DdXR2
         yT0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702043372; x=1702648172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qVfgea+2XXEWysBpQagPlt1NRhvP2C/6jsBi1mtm4e8=;
        b=ewzevOyTtgdg+1kcw0W1ab1k6CZ8uH+4WnFZAohyaDX5JdlpMj9AVKM2AntWWxH++5
         z2TUjfxOrUNEY7QfHpjzcZKHEoEJXoiB1swjIt6+NATaGbgYvS1kjr0SfkVuTKCvBj3p
         zqxLCEuUfw3VyMuMfHZgYwzBae2RHppct8JCBMDV2wEqDVp29gSJA11Wr+t8dh6JYSuB
         6fsQB7YEe/tzKEVP7G3L+XpLKhb64bJR8MCcefQBYVQLf0iDHH2hofFfo28H5GI0WYEX
         Z5vcL18GqHFZcNk5I3AiELQ7GKs9DA3RA4lz/W3ucAVu3iCOVGuANkgQzC73ydts6dQe
         ecig==
X-Gm-Message-State: AOJu0Yxuy1wcmxVY5HFFHWkR6pHIZDSq+iCJo/URwViQb30kNGnaVN9w
	KK3onYBaXZcNgRjh1ZVAaqA=
X-Google-Smtp-Source: AGHT+IGczQg23iZ8ZJ8uW+QK81mBTbuxiQBIbFSHayMmla817++3fKkRlmEenzq/UZiYWErcQdiIzw==
X-Received: by 2002:a0c:e907:0:b0:67a:b99e:4228 with SMTP id a7-20020a0ce907000000b0067ab99e4228mr4089631qvo.52.1702043372510;
        Fri, 08 Dec 2023 05:49:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee26:0:b0:67a:b34a:6626 with SMTP id l6-20020a0cee26000000b0067ab34a6626ls460234qvs.0.-pod-prod-05-us;
 Fri, 08 Dec 2023 05:49:31 -0800 (PST)
X-Received: by 2002:a05:6122:917:b0:4b2:cd5c:40a0 with SMTP id j23-20020a056122091700b004b2cd5c40a0mr138173vka.33.1702043371603;
        Fri, 08 Dec 2023 05:49:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702043371; cv=none;
        d=google.com; s=arc-20160816;
        b=XKFCgu8NKPlM1zc48XdHga/Lsf6SIAA8tKI6f3SxIdjABtk1CtE6wJc17YQ/dOKi3z
         0EuFDHYGIsrdstsP32ADlX8BAqipGIyaOUdI4kjopNgwwZ8lhTdSlZlXsg5y3JeyXIOX
         /nLGLVqqDqhDi8GleVnyV7VWDOQ2s/OI1CJKzJzuqv3+v/7H7U++jw0uXrNQBbTAYIne
         tLCM1/ww2s25tETwXur3113e5jDqDc2a5yh7B4byoxNXQXzZGiZqNF6+Za3Wyx/pa/vS
         9bV4TZIV98uz73LvpLNgQmdus3O/FS2l0+QJa3evQbc8IGBQy6eC/W+JUJPfPIhEoON8
         9NSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pyp/ZFyiUOjenQgn6G8kYMLVmsBPMd5m8mXyGEY1Mx8=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=vzvW45R9xmg64i4KhxOX8Oc+85lFmZ9Dp6edAdXXifqH4xGDYEcMBJlsUbD50ZNnKO
         WZzwTchhK7u4GfCC0WUhDo59tPZd0TwTTbVlKMA8i5ge/qBwAgtnocNqWbnMnwsgu2Y0
         jUMMhNeCwcytcqucpmHLW9xaGESfYzeKty4R/p6mGSwZ3MLEj9Klgj5wHbBwcN8rRbcO
         hRoKd/9C8mM1mT3/k6fwGFIW+jFByeHPBJ9/D9o+j7ZKKHyYCQ3sBQXCcnDDfgwBMXaN
         1OICtoEqfab0ffrKh/bXZitrU1Z6WStmcc4UX5cKuLc0xfhShBTXdWfeTec/skohB2Mw
         xdtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FiUpsH9a;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id g18-20020a056122099200b004b2e6e4330asi244824vkd.1.2023.12.08.05.49.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 05:49:31 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-67a89dc1ef1so11684856d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 05:49:31 -0800 (PST)
X-Received: by 2002:ad4:5de2:0:b0:67a:c8ff:1641 with SMTP id
 jn2-20020ad45de2000000b0067ac8ff1641mr5787725qvb.79.1702043371101; Fri, 08
 Dec 2023 05:49:31 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-14-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-14-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 14:48:55 +0100
Message-ID: <CAG_fn=Vaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw@mail.gmail.com>
Subject: Re: [PATCH v2 13/33] kmsan: Introduce memset_no_sanitize_memory()
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
 header.i=@google.com header.s=20230601 header.b=FiUpsH9a;       spf=pass
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

On Tue, Nov 21, 2023 at 11:06=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> Add a wrapper for memset() that prevents unpoisoning.

We have __memset() already, won't it work for this case?
On the other hand, I am not sure you want to preserve the redzone in
its previous state (unless it's known to be poisoned).
You might consider explicitly unpoisoning the redzone instead.

...

> +__no_sanitize_memory
> +static inline void *memset_no_sanitize_memory(void *s, int c, size_t n)
> +{
> +       return memset(s, c, n);
> +}

I think depending on the compiler optimizations this might end up
being a call to normal memset, that would still change the shadow
bytes.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVaj3hTRAMxUwofpSMPhFBOizDOWR_An-V9qLNQv-suYw%40mail.gmai=
l.com.
