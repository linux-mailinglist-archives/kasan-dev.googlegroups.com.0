Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXVEVCPQMGQEZHME7QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5609F6942FA
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 11:35:12 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id g63-20020a1fb642000000b003ea9b485123sf4583301vkf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 02:35:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676284511; cv=pass;
        d=google.com; s=arc-20160816;
        b=kQgE6VeG9vsmp+Qo4wKj/JjJ9kNmojVrCbCuQQVRcOKjJlGtiY2A4puQ4pvW7r1DHd
         7ipzWJivXR78QsSj1DjDR7LfZo86NY6ajtj3yQe4z8QWqrsk8yNb69oZZKvy5cOAUYCd
         j8VVbzsmajMC2m9KkOSl2MECkXslUQwiL09zFPdldKB/bcemB/H1AY3sgd75qzlaQ6xF
         I+adRboVZ4BaGvACn1AS4sK01b8UywS1SgInLI0QiaPyGBTKZuOS9m/5oKGRm3t8PNcW
         T5L6kMCUuJDaVR1y6L55VZYUicxmc4ac5nbK65J/gHlzHp8NjqgqAOdEmEjfGssUrwSv
         esew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4zHWYWZIts+daxZRbeITmylAsfy706W7evkNQrLTRlc=;
        b=ckxiV88+hj+y+OnxZ6aZl+8qBvRmKpgt1MiRdBXY62uY7lr70iN+xh2eP8lvawiiJI
         lFqK1FFjbNoi9DMXMAACGuRYhvwIchhiJZ5RuMf5Cl6LHbfdb71U7ZvNyzbXdQ+G2/f0
         yJT9KuKL++3yXMv0gzAkKNgAVK+MbtpomvidH22UsuuJ5+pLhfJhBK/y5Z/2x9pI5Ng0
         UbY45KWQJ+UBrvtox0kGLy1fYxUAr0hHAHwWMSXYwFiVcWI+MCuqJgor56chyFbcVRmZ
         vYOxpPJy2SKqVF8gtGspw4pmqdp6RRKOwy7f5zr0FItuY7KX/6TrvfhLWsFXW1id+MnZ
         wFkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q+UOAYFC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676284511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4zHWYWZIts+daxZRbeITmylAsfy706W7evkNQrLTRlc=;
        b=oi1pNNmxzwRpFDTmU0mZQ1E7wsZ+Y3nqjGIMT94Hal/zy9Tbg8J3+NW+/jPOm1iM0b
         ZCl4KMn0DKL4070ICT9bxYgMJn4+u9B5eEVGx7WaYoGqNcxMcRNfG6J59dtjWexrZeb9
         42DULNoF68rJwv2TcUkr9PP5YpTq+mTx8tbgeLSrt9y5CY+3Ewkucph0GF5tPtyJS/87
         YVLo7NQPWj/dOJdykFnLVfB2bXUQdvynWk8ZFG7RVFBvlQ+2oafXM6JEra6S5a5wTSB5
         mDn1TuCw9zEobTqFbHaCtPLwvy7+SBBoHMr+2DEGZuq+E4KP85n3iU/KhGsuRJJV4hqt
         +rpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676284511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4zHWYWZIts+daxZRbeITmylAsfy706W7evkNQrLTRlc=;
        b=6tJXuzndFVHyWUAyiy6/xPazidRDl4nsALxoBOX+3B1UH12Q6/MakB/4Tm4P9w9kpa
         kwK9kzesTdyacRDDfCno+aulHMJfl8HR7+Ll22+jH3gPa06Y8ZZarB5LeixSB3o49qFx
         c182N7Ou6bXvcuiAoqPKM0sFnOEpDh79zlWzBxpphb9dqHSTqBHnidzKcTrDdJkbG7xL
         nxqz62uo2WDmBHA9/6ApIagj1t4uKGXVHxfIQ/NoNHrzQgObQr6ywh87O9LV5tU/pN72
         Vc56d+7nHSID2ubpvwQu+ir2gbO+9wrgA3lOts9CTdbr0xbxc5nme9s1oPwOQS5JaPYy
         CtMg==
X-Gm-Message-State: AO0yUKWlukAqRGcvgETuG4QSJCxjXjCgLilOBHechU3WgyrxitJfphjv
	FU3JXKmx6I2Ke8tgq4lZKSo=
X-Google-Smtp-Source: AK7set+q7d6k/REXNx80JQmKdoMn2Cxf1NAh3WvqJ1XxP6JlZfjmUHdd4TzIAoH2rIzuOuUK8b/0Gw==
X-Received: by 2002:a67:a645:0:b0:411:bedb:5360 with SMTP id r5-20020a67a645000000b00411bedb5360mr2758003vsh.59.1676284510999;
        Mon, 13 Feb 2023 02:35:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1d45:0:b0:401:7067:19d2 with SMTP id d66-20020a1f1d45000000b00401706719d2ls461709vkd.6.-pod-prod-gmail;
 Mon, 13 Feb 2023 02:35:10 -0800 (PST)
X-Received: by 2002:a05:6122:1814:b0:3ea:84a3:566 with SMTP id ay20-20020a056122181400b003ea84a30566mr16875856vkb.15.1676284510297;
        Mon, 13 Feb 2023 02:35:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676284510; cv=none;
        d=google.com; s=arc-20160816;
        b=UkxKT0XYyLRlReO9blsNa3dOGTPgXKw3n6kykRkma83zWn+oygqr2n3PXN7uP29S1s
         I9Xjh/7kx6wf8GffK8+TiQGhO8WPpt2osfa6hXcgxfcUJXjaHoSnaeCvDH2Rja7y2aEx
         qdEGX3QKQQyNnEsQPEFB7WtaQA3uzYfyZ6qNjBa0to3khc+EZLpcoy4r1KvuvHKSKRIm
         nEz6z/Bxy3bXIUrf0MOwrvQe0cbXm18Bc/n1VC8rYA8yEHbxQNv7S4kmlsFdaYqo9jvf
         HBA4uwJnEArrbYUHmSkAdtVKFEAV93kzd9z4B06Qj6yb9FckevGq/QUfkaW/y1ArMTOA
         T1hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rg9iAwFg7IOMEVpt1NVV6rIqsGDrzeIrKjlgE6x+x4o=;
        b=CFfa8oKEZOw72LOstkJ2MC1wpdnYRk3H3a6/BELtn774/2WLWgB2ZIsmD1DR5w9HRA
         vDmcXiW9x5aMvYjF686wIFYlIRoEKT25u1fD08hauuaXHnimIN0AceeXKkhHDbzWUriA
         1QgreJ78/3XfNVBN2PkSSz0ZNGlol2VPmYwBsdaqg+EMAsDhiu113t6gRtPw0lgKvyWB
         PRhzbjnp/WtWqaMqxdAP+DmVQrYtgB12YgXAOfomNgPjedMkFnfZgQvSpuqPXANFI/DQ
         z5YBGLMDnvNKabgye8T3T30kyaOaL28m8HNRHQE7CnkQN6OECtFRP0/veqhx7Mdvd84b
         F4Kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q+UOAYFC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id ay39-20020a056122182700b004013b723d0esi587977vkb.5.2023.02.13.02.35.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 02:35:10 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id j4so4297736iog.8
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 02:35:10 -0800 (PST)
X-Received: by 2002:a05:6602:3155:b0:732:9e46:de04 with SMTP id
 m21-20020a056602315500b007329e46de04mr11808742ioy.65.1676284509903; Mon, 13
 Feb 2023 02:35:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <f166dd6f3cb2378aea78600714393dd568c33ee9.1676063693.git.andreyknvl@google.com>
In-Reply-To: <f166dd6f3cb2378aea78600714393dd568c33ee9.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 11:34:29 +0100
Message-ID: <CAG_fn=XsJAZK1bPP7KXtTOk_cZhxc6TwWZksB8w77Dfhpy4hQQ@mail.gmail.com>
Subject: Re: [PATCH v2 08/18] lib/stackdepot: rename hash table constants and variables
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=q+UOAYFC;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
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

On Fri, Feb 10, 2023 at 10:17 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Give more meaningful names to hash table-related constants and variables:
>
> 1. Rename STACK_HASH_SCALE to STACK_HASH_TABLE_SCALE to point out that it
>    is related to scaling the hash table.
>
> 2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
>    to point out that it is related to the number of hash table buckets.
>
> 3. Rename stack_hash_order to stack_bucket_number_order for the same
>    reason as #2.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXsJAZK1bPP7KXtTOk_cZhxc6TwWZksB8w77Dfhpy4hQQ%40mail.gmail.com.
