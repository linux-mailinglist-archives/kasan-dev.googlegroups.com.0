Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGXVVCPQMGQEQOV5MGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 43C996946F2
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 14:26:52 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id c8-20020a630d08000000b004fb299589a2sf4676093pgl.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 05:26:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676294811; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQTnGI8g520wNg5VJfB5yMvzVD2QkCJ6M//hYzeFR1IY17mtzYdfGvrKLjvnVdf7RE
         XvIQBUemDAGa61MTqONTqBNPw+otWms6Y1LCp454zeIq7xdGGUclgpS7EU0ZaT4M8EAm
         +2+MdXB85Wsmo2+yAPOc7iX9b1ll3cVhQNLNkTLbP8qLx1B0PE7qMFgjFD4ZbBFugYpK
         LVMQamAL7/lVnce86eu+moejraR7JAYM139I5lG9t2PFuZ6HuabLwhI01UwyJjBllTfI
         RdVOC12nbH7Z34TVREhP5qXmguj+RY/4UuvZP4OIlLC7WIcftM/qHSJYlT564V59jt3B
         xnyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sr1yddPq4N2BQG/iSds71Ve8BYkKjq6Lqrv/opCtVlY=;
        b=0b9qa2DR3f2izOBtHJ6W/qFszzA5aSDPDzWCDv+/dKMwnUtBv9IDC8lwJ2zTTxP3oR
         B/KGrrvXWzhibwLVnkhgyGZ6vaMrCW5jzCH6oXZw+TJpvoNcH1iPzm3Sz4MNrRMFlyKN
         FrTxCOoK7oMkVdfCI06P9A89osF6ZpEhvwqD8XKh7SGvPr4njo/NFKeaxx0ZhEatm1fO
         /eZAYuynkwLubcImjywAMHhUpX5427Wj9zV4eOjEjwv36nL1zqBL1ilttke3sjCQBJmz
         IoYIDY3WDWLiygzmXSQGgMq3KVPsjoRDqub2MXeaNrYxp7O/hnk7D5NTF/Ib/WTi9iWy
         eP1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q2jaAutB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sr1yddPq4N2BQG/iSds71Ve8BYkKjq6Lqrv/opCtVlY=;
        b=KMFl0i5HJ2bXQvQzK1ezqvewUPjAogty1akjUlRFL2E0BCvUiqCeqAT1ri1owg954C
         vrIls6Vrzt/CMFhMgpE2vbqaneSwl2Bq9qJeB5wKvxoF3B9Fy7dt/Z0+wiKMkMZTxPab
         Z32MapKMMlzf2PcKWJAaiTGpS89CaJzPYmVoN6tJtGNS2r/MCieDfRwRW+XdHT8A+gHR
         DpYOLS7mcHOUFlHNzbF6Mrvx4ogCujDcgwsA+TsG6Z7BV4ZG8sw789gU+WRBbMFQR/ov
         +h/LdYwwUAKEYO9pNLLsJPJsU0H5xrFTjmfBGpvWwL4GTJK0MVL09SQDTz+ULMjt4UXW
         iQjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=sr1yddPq4N2BQG/iSds71Ve8BYkKjq6Lqrv/opCtVlY=;
        b=QlczJUB0CKAy2Ry5hJGc/FwBWNE1eb9LhNzOLhpCIvJnzXqTQN5CrjMi8e2yrekQS8
         D/BrKEDqaMPjDV+uF0GTCZcjKWbM2acGondT1DN5hwh0FBt7nwSdtu4rvOU2pOeG2Xt9
         pwlZ9ceG4z6nBIjMtpsBjcinyqfJ+StCm7DJgqDzdnTDDfsDv1/ctvZTCR88I95fKSh5
         iYRvjgR78cUv5coLtzfQrxKt9kCpY5JiaKL9Tw81fs/Zs9rqfDml9N9WSxtfLyre36uq
         nWUG/BSdIkDNXdQXHwzjIIdrPubI7i0mxwgjD8s6sQ5YQYVVp23wCjY0UbYeLCOr/cmo
         8qfg==
X-Gm-Message-State: AO0yUKVFs9F0gg1Fa77CvQFbPUnp0sS1BQwXmxSTCakaJXwU5DK+lFM6
	oxCi8qpKU+spX/qd7/pgu8c=
X-Google-Smtp-Source: AK7set+iMG6RAfX4Kp3U3NnAxVoTuVMdw8Uw/v6BsYe4BNTpIgvqVvzoT0w3VjfHYMjz9HAeKITFRw==
X-Received: by 2002:a17:90a:2c0a:b0:230:c4f5:8577 with SMTP id m10-20020a17090a2c0a00b00230c4f58577mr4264113pjd.20.1676294810758;
        Mon, 13 Feb 2023 05:26:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ef51:b0:196:2e27:844e with SMTP id
 e17-20020a170902ef5100b001962e27844els12707266plx.7.-pod-prod-gmail; Mon, 13
 Feb 2023 05:26:50 -0800 (PST)
X-Received: by 2002:a17:90b:3ec7:b0:230:c6fa:9304 with SMTP id rm7-20020a17090b3ec700b00230c6fa9304mr26643945pjb.9.1676294809994;
        Mon, 13 Feb 2023 05:26:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676294809; cv=none;
        d=google.com; s=arc-20160816;
        b=z2BXTFutyFMNGR82fPXlCZIB+fVDiLy2MBzbX6lZEL9fs0G+AH3ykNXIyINDh2jAxK
         69VIseZSn4C+68gBtaAHg39ZhUfejCOyFEU7lRIrDYPHB2vJhuImqA18+BH7BilKRH1/
         ww+qADBSoLWLhyONow2Qa+Lcqw/IaJrXXOs2od/JCbdIHCevPNFSfriXZg7ix7aWhtsZ
         gz0gTKBI3zAK8EFJslBXaD52ggt4A3D8UAv62KGj6u9+hkkFORuexqa9UV/WOHZfNHVE
         OuYmVKWYfUsWMiS3FRo9T4RP+Fkdy8lZuCy6wG5cJzyB1zlAAqiNTV9JF/b7XYEctvfB
         R59Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uPqhzuCoB0XLuHxXnDgI9ge5QiksJXrToVJ0PRvFH58=;
        b=eNxJIYwTaaWJpYvERhZwzuIfm/gFoqjtDNel0BTbYkM9S8PhyJ7dVpHlDv90CchfFo
         kukBZe6vzSITSbC/tNto5N3dtbDA+iNIVDT7V+i+46S4k6M6w+pynOAJgmpEiQ5Cn+/U
         8TWSfzbveey3nT7MldR9hAmTDo9k4wSRSm/ObMLKMpLLOaOvQ6WSJF8UcPzdgdbRFzKP
         779T4/HeWVen4dCMuiz01Wu202TopxDE+mIsBHSKvx/Ux7xAWTkvwQLcjaMh5PpQ5BOq
         pPTjXIzwPsDsv/5vgp/kLLErue0rMwOqFJkKPXgM/ygafAIVtXk0RjWotSV61UWqodIx
         Dqug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Q2jaAutB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id v3-20020a655c43000000b004a3ed20c3c0si859711pgr.3.2023.02.13.05.26.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 05:26:49 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id y7so4436474iob.6
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 05:26:49 -0800 (PST)
X-Received: by 2002:a02:a794:0:b0:3ad:3cae:6378 with SMTP id
 e20-20020a02a794000000b003ad3cae6378mr12315142jaj.16.1676294809275; Mon, 13
 Feb 2023 05:26:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <5836231b7954355e2311fc9b5870f697ea8e1f7d.1676063693.git.andreyknvl@google.com>
In-Reply-To: <5836231b7954355e2311fc9b5870f697ea8e1f7d.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 14:26:10 +0100
Message-ID: <CAG_fn=VM34NfOhir_3y86=SKxZ=PqbC3DFuFVAmLEYp8Z9Ax3A@mail.gmail.com>
Subject: Re: [PATCH v2 17/18] lib/stackdepot: various comments clean-ups
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Q2jaAutB;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Clean up comments in include/linux/stackdepot.h and lib/stackdepot.c:
>
> 1. Rework the initialization comment in stackdepot.h.
> 2. Rework the header comment in stackdepot.c.
> 3. Various clean-ups for other comments.
>
> Also adjust whitespaces for find_stack and depot_alloc_stack call sites.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> - * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
> - * and free stacks repeat a lot, we save about 100x space.
> - * Stacks are never removed from depot, so we store them contiguously one after
> - * another in a contiguous memory allocation.
> + * For example, KASAN needs to save allocation and free stack traces for each

s/free/deallocation, maybe? (Here and below)
> + * object. Storing two stack traces per object requires a lot of memory (e.g.
> + * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
> + * stack traces often repeat, using stack depot allows to save about 100x space.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVM34NfOhir_3y86%3DSKxZ%3DPqbC3DFuFVAmLEYp8Z9Ax3A%40mail.gmail.com.
