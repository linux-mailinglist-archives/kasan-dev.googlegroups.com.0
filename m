Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6EL53AAMGQEL2NFHUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E1D30AAE61F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:10:45 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e73305b651bsf96556276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:10:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746634244; cv=pass;
        d=google.com; s=arc-20240605;
        b=D6+nKBCoud7ikRWxWmZtKWR8+783kruS4caE+muXpUArOMZjkF575NaRYUPxgS65QH
         QddhK2tNyNz+zL1jjWrwd49MEBMcUWBqs/8ov4jS5f6Dtl+vFI9ZWbeDJuACwqKIDpBK
         6L2x2DL+9125g8UaGTi+6dqxUbtR8LzY9xNMhRro/fdGDl2nGaClV4zzMiKf9iGF2IXV
         PId7ptiXVREQHOdoMeJ9OZ6Mqx2c1xcPtSsf6RT05IwuG0Ai20sfLJxrheO3dZhiD/N5
         mlAW/lescH9eud0LSnt4cndSAR7oHlXxpqNBoz8kOD9sQgypILS+9zH1mRb5t+4TP3wG
         4AMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aL3cmbMrWvGT47AZEYlB4qKtDMXwWBBloJ6wrFf0kJA=;
        fh=rAH81Xc9NYS7Re2LJXlW1Zgy1Hi7KGcBw+NWA3Lhl8E=;
        b=Fy0O8j/juhlrYbhJyTiG5QIwYOT9hJtnIscfjVeODLyGtUOjvRvU8ua6nsi6lFcEvJ
         jsS41EN+T9O0n1TyMJPysKWadH87gL6aNkL2bysbMMP3+3bZhqeaHW1Vp0KtB1K/IRjU
         dSL2uiRgGTKyUUvrMjUFYyhCanEYCjQVqUk6tA8LbL77YV1L8wU5LMEe9VubBW56Q1vx
         fXtzvT+x9Np92w2UqmtZYdw7iQVjlkeeeGn/K5ZICzkkAmNDRfQsPFRrI/4Qt3Mpa3qy
         NUDXU67weKziq59S4vYFTHGwp9e9vC1a0X9meEeuRsZKxQKF1wjoSysprQDutwJPW8WV
         Dpgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t8qeJGCZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746634244; x=1747239044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aL3cmbMrWvGT47AZEYlB4qKtDMXwWBBloJ6wrFf0kJA=;
        b=WIuWHZu3Hb/4xVHZCNf8De6qhY40SzwoWTjDjHE53zVawlrBHukHJ/AI9MUdpotFUt
         cAc0e9CjFnYvgtzC7wqObXQW5mwX8qY8ivycQE5oYdi+jJ/ePwir69tXrnYM5Fj7fvWk
         3zmEvC+KrP6lAMMkjYuixF/K3DhVVEs0/BU46cd+P/1qWcCItZdJk27M+R5Cwuo87Snz
         HnHGu7VSrzQJwoCG4P20gutPgCubcZ2OpvgHYd1ablQovbDj4UfxxMShMuk6uz36V1Pc
         ofu/uCYAmQ1bg/2cYzKkgp3LG0C6a+nOcz8ZnJuC+iSaPMzMaiLiyhErtg7X82F6nl55
         Uozg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746634244; x=1747239044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aL3cmbMrWvGT47AZEYlB4qKtDMXwWBBloJ6wrFf0kJA=;
        b=HaSu1LLG0RM5KgSKYFiU4K8TH2pKoT7aQCIRgCHdWNBsGBRoIu1oSEqJrLhzGtJGPz
         A/sHqODW10d2SlA13k9SZsRioFtIneDn3g+T8G7s/guVj03nS10JyXC5IfRfBPnscYGS
         cGoWP9RheQH1PPCzoNuhEp9RRCfPZtCTE2f053rygQLvU/Me3uC534SMIYX3mpBMtr0G
         ATIOP57C94W+RtpwPvTcamyCgTNpFQuJTXVl/DDnn7UC7JEEtY0/1fOxIiHvh02Do8l9
         Y2uSSXRaS4JXr7qMg+CPbF5RrmEM9YhyvxAALPwbuxn/tOFs8jc1b4HR7iHIWy50QSJS
         w3Og==
X-Forwarded-Encrypted: i=2; AJvYcCUFFlQqCv2/jW2yFKLwr38wKb7wGhjM+SSY+sTyFkX94kM4dmUjzLf1M90bymk65PYmkPTeXA==@lfdr.de
X-Gm-Message-State: AOJu0YwNUOKYI0xxAVXuPxRGpVXnkJUAqjjSjAfJSMysycHXCHKSzAjG
	HCLOkBW1+uIwxcZwoiG8Qrb4ZeN2q5lpJ2PTGwK5P38RXyrzNsD6
X-Google-Smtp-Source: AGHT+IEm8nW7HarqvbiY5PUrNGzH296rs4irG2pBtDiKekyjh/p18EMTla7ZNI6Xyf5oyqimerO/qQ==
X-Received: by 2002:a05:622a:190e:b0:48e:5cda:d04e with SMTP id d75a77b69052e-4922719e194mr52218871cf.36.1746634232943;
        Wed, 07 May 2025 09:10:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHCNnbfdQCBS+cVw0BbrAcRJ3OkTrbKEnbUWL7vwz8zAA==
Received: by 2002:a05:622a:180d:b0:476:734f:a485 with SMTP id
 d75a77b69052e-48ad8bc2475ls34174431cf.2.-pod-prod-02-us; Wed, 07 May 2025
 09:10:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3Czs7d6KCHCu9W5ZAe/YTjNYsXPmDBxgn7kZAhMs5jRdCbku8YGxslzGakqSz5vJpEv9KfoHK+EI=@googlegroups.com
X-Received: by 2002:a05:6214:29ce:b0:6f5:3cae:920f with SMTP id 6a1803df08f44-6f542ae34b8mr52404236d6.27.1746634221843;
        Wed, 07 May 2025 09:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746634221; cv=none;
        d=google.com; s=arc-20240605;
        b=QuWLPWEmYDGNSCR9MJU2xSmLrmniSKrohJxx4un0tZs2YKSvkzINB6P6FqvJV8afFe
         CLi+b2uhaKCpCqT6Ps4IuZrgp4byzfcmd5XFAIPmvhISV6SK3jTVcyp2l9azceElk6nK
         4wO63MXcuNHqmsETtrmDPDHe0n8iqJnVnMjVDphmqVAe4hvHmuLlkFY5Jeu3y5cuisYx
         Pc2yHEVRnT7ynWuSweXRu2N3ZJcB4Smiu6JAw14Ngn6n8suBRli06nYzfeGgus3Z98lE
         AuVtdNK1lFq3NCSbQuc6MoChQeckUYAX3IUkWF6ndqemWuYx5GA+Ac4Zk5/3JWi4zx1u
         E2Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a4Sd2c8Ti5AoEGgOG/K+kjd1zjv+xJVe2V4gU11HvEQ=;
        fh=1kC9ArU9cyGB3khrW4Je46hWsDaZ/z/2sBSmpJm9HD4=;
        b=kibPfbwn80Y+rR2RGG21b7tm7s1Upe5pNWsGXTYN921RvpTpB7AGfcYeBFJlZQdcJ6
         EcMj549+gt6Xbrl175SiN2T5MkAZovokHVJUmjLCYtffkeo6VUwmVHBUvQlEfbEM5moJ
         5hJnCEtOUdNu22CEGrgg0x+AQzso7taz/f8aNaRjYKNHeaHmOH4ragkK5Ca6o2kqnlto
         nY+dRMBqNDrRJkSmguHIP1PCQVFkbqVaTblcQ0E0e+Qtf3YEsgKj6c2XI71HnwV7vJgs
         CrpbMjFmGJMdLqzu4RkpEddbOpr8BuhgoZRJzQ7mjKXCj95SbRMZ1Y2UqK8S88o8bBJu
         rnHg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=t8qeJGCZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f5424f5186si369556d6.0.2025.05.07.09.10.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:10:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-b170c99aa49so4530312a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:10:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtNFbGLUQMiXIAui2JddtyAfGg0PXJ7vmXcdKd8v8KU6u4qbgnIgN3Dz2pE2EBnc6vARxw/PiqoHo=@googlegroups.com
X-Gm-Gg: ASbGnct34E/FappEwOBYiy0Y4cJlJUB6lEiRN1w9xeBV84IaF4rjkd0EsKtJLjRsgnO
	vVgyStr3bmeliEUTo+S9RsmbBL7Fnb4O+JPt4bh8irByqht/+sgkddkWYaxQd5j0+d4YlaEs8Hk
	OjpBG0usILfk294X82Ype7R4tXhd18pT0jBEyy6cHYJ+zFkumjk3qEk4Rk0X7Em4eq
X-Received: by 2002:a17:90b:3882:b0:2ee:8430:b831 with SMTP id
 98e67ed59e1d1-30aac185bb6mr6495731a91.2.1746634220697; Wed, 07 May 2025
 09:10:20 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-4-glider@google.com>
In-Reply-To: <20250507160012.3311104-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 May 2025 18:09:44 +0200
X-Gm-Features: ATxdqUHrTK7nVqScZrnpkwHmKnPptoRfaqMqa66xS1OVQOUvwLopYzYYbtDamhA
Message-ID: <CANpmjNO6aSwyvsnfcLs1fd8vBET+VaVx2=AX6WcVGJ1tZqcv7A@mail.gmail.com>
Subject: Re: [PATCH 4/5] kmsan: enter the runtime around kmsan_internal_memmove_metadata()
 call
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=t8qeJGCZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wrote:
>
> kmsan_internal_memmove_metadata() transitively calls stack_depot_save()
> (via kmsan_internal_chain_origin() and kmsan_save_stack_with_flags()),
> which may allocate memory. Guard it with kmsan_enter_runtime() and
> kmsan_leave_runtime() to avoid recursion.
>
> This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=y
>
> Cc: Marco Elver <elver@google.com>
> Cc: Bart Van Assche <bvanassche@acm.org>
> Cc: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/hooks.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 05f2faa540545..97de3d6194f07 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -275,8 +275,10 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
>                  * Don't check anything, just copy the shadow of the copied
>                  * bytes.
>                  */
> +               kmsan_enter_runtime();
>                 kmsan_internal_memmove_metadata((void *)to, (void *)from,
>                                                 to_copy - left);
> +               kmsan_leave_runtime();
>         }
>         user_access_restore(ua_flags);
>  }
> --
> 2.49.0.967.g6a0df3ecc3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO6aSwyvsnfcLs1fd8vBET%2BVaVx2%3DAX6WcVGJ1tZqcv7A%40mail.gmail.com.
