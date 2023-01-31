Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVPB4OPAMGQEOEHXLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A827682ABF
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:43:36 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id i11-20020a4ab24b000000b0051760012060sf1009068ooo.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:43:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675161814; cv=pass;
        d=google.com; s=arc-20160816;
        b=vEJy2k83w6rt/7MEd8ZfE/lQ72VGLlAmqEloVDwWpqRbizWv5b+J1O8DVMP+0wvBDR
         pUq6RlrWVgaikmXLTrJjAfOOsPmTNA2jZYQqrQhNBK6E2rLPc9Q6znI55NEY8Ua46Wv1
         frmgzDeR1rZS4pmMxVrVGvwL6Ww1zRHd7YIvgw/x9Ydx4kFr0kFnhxgMQo72YfWPxkh4
         STH9/ukwbIUE3RLsxoYHsG+Ed6nbnH09yoe3iKL/lxH/Ib2MI2FHISgn0HnYWBRfNOJI
         kQD7qzDeZOU8jc0kD93rMYp02UOKKxMWEcVfjmHXiOoy1+bmuLKs/ooxFoJd8wDbLf9S
         J/RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O2Xwube/u0dSqQTq5JUM++xFm9Y8Ek9T4C4yid9BEFY=;
        b=fuXWfluZ+YNzUXJ92vlkEx+4HGB1lom0t+WrP6FoT/v2eVe0tWMGQrZZVywUHnRtwG
         vCX8VjJ+wALha9jihk9lxNf/Lf57UOQlB7mQAbZUEi7tnK0poHA8XDaTlNAexzgNGP1k
         1cEmHyGKrGsKwwwvLbLAEjvlyceF9h5dwefAacddYtYktXdUjEDx4BaQvc8MKtZX/ak+
         6IuL7ey/PgGoVkjzzWMLxYNXomahzKZ7RHeKaAbR6beD7G54iON59ZVA4JtCXIu0INPH
         XvOwWuRHkES82z3nIR2D3Ee9SVclYE2OueOnVvHZEy2Dn9vmf6Qxk5p81zGU3S0ehDPh
         FpHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=enJHYOBV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O2Xwube/u0dSqQTq5JUM++xFm9Y8Ek9T4C4yid9BEFY=;
        b=RLmJOjeyrhgWF20hr64oujt+8LOeSUDRvB2zu+NqQQ84pJFX58mEpEmDdDtDxl73kh
         DuqjV7RtV+WvUnWZsS4nref1C+9Q0sSV7zN7Qmc2osy+aAw+osLTyBx3yaorZ+/Q7E8t
         KBOagVeapskXo0+vbga6mxEBH+BuuqBKz05B2eo/qysbChOb40gMR9jTM4YMFKRaHb8q
         ALvA4NDRy8HuNzaqzMpyteBK8NBx1TQy9LEGP9xb6lMmi8kF4s3Qc1RZXHYXXa4ms/5C
         bCsO5/uqQvNAwE1NTcuZwaRZyRMIy+Rh++2sGwvKAR0kbEnb6cCk5SACewBTzzmiDzDJ
         G3+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=O2Xwube/u0dSqQTq5JUM++xFm9Y8Ek9T4C4yid9BEFY=;
        b=W4sB1wS9wwIKOCrRZOtfd8f5Yzqe8uIv+nH6Pq6If0TTzp9jxX4VU7WGM3YG2C2lMr
         Oca3BvcKl/vQ7IjApxh5XHsimV4kGfsr3imXLgBwlX8hyiuyjw6huiPU99mQK0zu6HkU
         66RCvlhfpCd7W2xH1uFi/pqpLrB+M0J3hotuCY2Yoz0mSpLuDKvQb6Tq0bXV7IULReNA
         BskPlXGI95m6seZ8M/ddftwY1t8n1N1xYvFdvlDcnpx2DGUiMhsJNnCvY/ZN4KNsZM0J
         9VCb6ZCT3clohyyhaODUNHO5LLO1BodqfYxtPmDicROQHu/1RY2L1Ckz8hNgr/q6E8XN
         QpUQ==
X-Gm-Message-State: AFqh2kqEJrVOHReOj6mOJ56gnVVtiQzBVdZStDk9hY3v94fDrdhY0xSr
	DYdbLdzP+3rtKaxkpWKOB8E=
X-Google-Smtp-Source: AMrXdXsyhv5g26oaKCRQUABU6GohkV5L9h95hX8qkNagoRJI6MVExxJWO4GL4S8ko1jhF9PX3Vslog==
X-Received: by 2002:a05:6808:2902:b0:35c:149:3428 with SMTP id ev2-20020a056808290200b0035c01493428mr3710005oib.180.1675161813682;
        Tue, 31 Jan 2023 02:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:d0a:b0:66c:7df0:d6be with SMTP id
 bu10-20020a0568300d0a00b0066c7df0d6bels2125339otb.8.-pod-prod-gmail; Tue, 31
 Jan 2023 02:43:33 -0800 (PST)
X-Received: by 2002:a05:6830:1e97:b0:68b:c92f:9017 with SMTP id n23-20020a0568301e9700b0068bc92f9017mr5050318otr.34.1675161813327;
        Tue, 31 Jan 2023 02:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675161813; cv=none;
        d=google.com; s=arc-20160816;
        b=gKpkhCrfRqoDFBWpgIaeGSITpfF0ne80HO7yhC8ku6DnMkjPBrAJZ+yGYhjYUWVxP5
         smfkKSu6pqlLAjnxP8Yf3viz76p9uuLvRrcLyuD5a1URbAERtTTYDkoUm8JCyVG/XqC7
         PAMtvlbmO9G5X/6BUyiXIgZBiIsbjybuXVb23O7aIc1EdiMvJv9IcRNKUfmrjScTaBLN
         0pUUxiUPN2xJAMG9ybH6QAHrgGcnFagow8phoA3EgbDnQ0H1n2SXQ92dIAcKSIOhV/H8
         rMd4iEkRyuYVbDDNRKnZcvZIDAQrO57Mq1iOWWYT2u8tzpfv7Rjg8qs1RBpG4t/cGsZG
         tUUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M753LZjz9jIM5UZsN6i1l5g2fsIv/6aiQIsgYIsM+/c=;
        b=VMGioNdE6A5lxzH36FPJEQ/F3NLJrAyeWAK7MUrmM0Qn+GG7W6ucdtltgjAeYARTJl
         b4g9bM9NVLutEWm07dZeGweI/cXd45pj8Tk8BPxR88lBah/7PY6dVH3VqEBEvfZK/XJt
         rtrGcrU2R8JwfaoqTcuhUoNPvxXbH8BRgRl26n3M2SLAQOLAT2K8vYLjFeDbFvbAQ41Q
         1fCN7n/KV+ftzSHou7Vx+6eNO+IwQFTkSQaJn27ob4Gu8VynoG2gJww3wwcHMEJxnc5V
         eCndjipKTjsZ7Bzg9jOW8Gjx01tyzhQMhdtVlIPbCYqwkVzqoAgFomayhJAPFkbmH/cd
         KnYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=enJHYOBV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id bk6-20020a056830368600b0067054a075b7si1872260otb.2.2023.01.31.02.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id 187so15552298vsv.10
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:43:33 -0800 (PST)
X-Received: by 2002:a05:6102:449:b0:3fc:3a9e:3203 with SMTP id
 e9-20020a056102044900b003fc3a9e3203mr634380vsq.84.1675161812760; Tue, 31 Jan
 2023 02:43:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <4ed1d0828e837e15566a7cfa7688a47006e3f4b3.1675111415.git.andreyknvl@google.com>
In-Reply-To: <4ed1d0828e837e15566a7cfa7688a47006e3f4b3.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:42:56 +0100
Message-ID: <CAG_fn=V=91XNUyaWuwrgDqNKhHcEQFmD7Q4opc_v4vos+GR3qQ@mail.gmail.com>
Subject: Re: [PATCH 08/18] lib/stackdepot: reorder and annotate global variables
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=enJHYOBV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as
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

On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Group stack depot global variables by their purpose:
>
> 1. Hash table-related variables,
> 2. Slab-related variables,
>
> and add comments.
>
> Also clean up comments for hash table-related constants.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

...
> +/* Lock that protects the variables above. */
> +static DEFINE_RAW_SPINLOCK(depot_lock);
> +/* Whether the next slab is initialized. */
> +static int next_slab_inited;
Might be worth clarifying what happens if there's no next slab (see my
comment to patch 01).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV%3D91XNUyaWuwrgDqNKhHcEQFmD7Q4opc_v4vos%2BGR3qQ%40mail.gmail.com.
