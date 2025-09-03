Return-Path: <kasan-dev+bncBCCMH5WKTMGRB75K4DCQMGQECX2P4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id A48DAB41B7F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 12:16:33 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-329ccb59ef6sf2271295a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 03:16:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756894592; cv=pass;
        d=google.com; s=arc-20240605;
        b=IDKLuhPBdqtXhamgTHF5x6L/Yma26NA+Gk64Y/Pl8wSGeWhimDR3E7Td/Rmm2MmBRa
         aGqx3gmV3B14pUlggXFtFMDdAOmfIwn08njJlrxHig91HeCwqOn/4biwBVxq/wbehOWO
         QQnylyDUMLwKHrVA6BtQO4pPT1tYvI8LAngCvdl4+JV1grcjc9c1hKUIc4lASNb7CG/+
         xiDe+9+8hku2wFK0J3ATdyqSSoB294dBV820znVam1Th9mR3vVmeV2fmNMEI1IKD84iu
         7d9yOoLaM2qSgEbiG00HiHV5T5zwZQP0ayn4o0G0L9DlfrhXPssEdKZ2Acbv61ayXMvK
         bFAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=43ZOcPYWzVfMaO7TLi+idlg5U1FhjopcHZQ6Kd+pFVM=;
        fh=akv4w8NmOgep96U1PGME1b9N0KbEetuTkwb79jEnC/0=;
        b=gCnMP/VWlCVkoIkeDnHAVQVr8UbMCNMAAQulayB0psH0tZp0FuIodFyIorEQJI0X50
         QNgXyyBUpC8hWeGidHG7xmrH45H8qAHorbUS73lmTd326rLtvVl01FBBZZHvuaiOnatO
         5XZPEoOlQPQtIcvGDmcU3+hSF6jAxW0Dmj7zLXFwFTES7+rW2+sZKYxEzA0mEXY8pTZc
         L/r9ymi8EmkGk3kFH7H6eEkCQdILHsYtVEQHoGIypYxzbQIth/cHXMP1ZYvbJx+44lRf
         Ybx3a7epr6YeWI6CD0rdk1XsTQAnLf+gGqU0P6C1kPdQp6giFWipZ/SeqDcXejK9kD/5
         u9nQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=drOERxTP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756894592; x=1757499392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=43ZOcPYWzVfMaO7TLi+idlg5U1FhjopcHZQ6Kd+pFVM=;
        b=d2GGuzbISV6Hn+kB1wo5tYZ//c8xKGeuzPB366j1GnOJ2t+ZFsA3IOFiZCnQCms/Dx
         gvNJpFD1ApB9qxiUHg+m+j0XEukZZtXT1SkAdkBWMJNgbfiMwXOHYkPIYUAEUcDETXaO
         Xhkpf9tvbptRc0taOQndJGb32Inpzdhy5bY7yfRc9gucgHbIMiS73brNo7MiDSteVBkR
         52+kEYUpKR1EMADa83TRoowJ5hOZM3CrskP3NArMjlGerNLqYNCxMUzFaOzbNEzMLUl4
         K4S9jXOHqXEYF5RYbu6vYq4eNNlOCxcb9FaxSnPFgag6CZaNVIYmyikXy7ueoPC1NQHx
         IibQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756894592; x=1757499392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=43ZOcPYWzVfMaO7TLi+idlg5U1FhjopcHZQ6Kd+pFVM=;
        b=EdSUv2GLnLtUz2NdxTaRRuLXRtUmES8Wn8UqX2wYhyWslMK2dAjny1KZ4KjQdZaiIZ
         NIbWgwFG1om9CBUSXeM3EmI4CTCq2nLYRzQGiz8+r91+CwsahQVBbowNd4/5iddKVUyH
         K72t/2pD4dPHjJcUTWOadfyQYyoogoNSff8cS5CItATYYKnRiN7Ullgyyk4n2n7XfBE0
         UlRViOXatO1HNTGatT/TPrvdWmy3b1a10SwlmRB0yqt/z2tQZyumFS2QFsAtBJPv6Bkh
         Wkd4CQRt+1XzHua1IShuQofAB4v02OzHmAACXjUmF6Tob+xnlvVk2cqKBBgMGtFb/H3E
         O6rg==
X-Forwarded-Encrypted: i=2; AJvYcCWqLn7HUyAnJAipg1n469juZ8adt8nL7qO5EiT713ki1/2FrAEUpw5AEXJxWBxABWqAbeIPMQ==@lfdr.de
X-Gm-Message-State: AOJu0YyTuUUXVahOhgwjqbTF00DnmmJq30jsfrzJg+nKF/MM6nM53OMd
	Dy2zgsQLXo8KeNtZ+PLpMecaMNwvu9u0fj4ZBT5WxXXK0csfZh6DJG2z
X-Google-Smtp-Source: AGHT+IHaEjjpmmk/AYX3WTybR0GtHP9DltQLWJ3+6nwni7rErqkVZd5DRJ/rzgi7irU3TrNHa1yBuw==
X-Received: by 2002:a17:90b:4a0b:b0:327:6f34:3771 with SMTP id 98e67ed59e1d1-328156bac53mr23037857a91.17.1756894591947;
        Wed, 03 Sep 2025 03:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeSdESqIwZPssmeSzkKf9DBhztri8AaQF3Xldjt3BNsbg==
Received: by 2002:a17:90b:5518:b0:324:e853:c58 with SMTP id
 98e67ed59e1d1-327aacb17b5ls5248191a91.2.-pod-prod-09-us; Wed, 03 Sep 2025
 03:16:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXr9kD07QTL3B+nhCPFRoZZJAxND/YHIzSvVw0BZzqIeIDLvbWPapxOvB/puVfVRD7a8oYZqLJJX7I=@googlegroups.com
X-Received: by 2002:a05:6a21:6d85:b0:243:c9d2:e0ea with SMTP id adf61e73a8af0-243d6dd1223mr18315728637.3.1756894590288;
        Wed, 03 Sep 2025 03:16:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756894590; cv=none;
        d=google.com; s=arc-20240605;
        b=PgDFNrry4O8tOW0nanF0wislf0JYaI5U6d/16+8D2tnLtX5sjXnUSwMQ9ctBJjxw+5
         9Li0PNhn1dRnTZtWdjKcg+MuOGwhcIen+atW5gQWMuZxiG1LSz8v0q5GNrUwno6bu7uB
         oGhO9PVjxjdgFFz/GmRH9AHbTx80qHdzSx2+IJIsUAAstPlXlvfSPvzNycKJkwuC5vA0
         56419WnqOK1vVwVjWqRPcvaeEF363sehNaR2LEFoHHE4kNYnYf8A6+L146wBWeruSmRD
         2fHuIQhqCO3k0EwKU/0hOt9RcneGbm0Pb31xF+S8GojBjPphK23JVmY4C/77rTJYW6zR
         ixIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vysyoass8/7fXChxkNXCAvtsZyl5TuEWzgR+DsRg3BA=;
        fh=D4vTMCxbjtnwsNYZUAsGkjRG0A5A/ZJXhxaBMm62WEc=;
        b=K5eDRmxR65hCNaTLdgS+N9L4DbOmHVwpaO+PmMO0WjXTHVX7NKqkxQ9Vfow0N2wFYl
         DWYhnpiIBRRSSbnsYULgyOa8XaUzp4ESwZc7/oN+ipQFtkDY3zWU7dhoUDj76jUxs4hN
         DX9E4F/bhVTeKxu2hLQ+U7mUtOy/Oro95EtrK96eSUkf3Jhrwv31Kt3gJTRQh/KLpvgq
         hgldsz+ZFJp8Xpbf05QaQVaLiYQZqHI6jl+G6KBkzSI6Q72+l60ErmpF3xIOLg/ppDEl
         SIH8PMqstVnXXCxxlz+hge1pteD0M7HOH9zEjWkRSrq6gntfG1YbJGF1TGI0Eq0t7qEs
         3xnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=drOERxTP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7722a4902b1si518296b3a.6.2025.09.03.03.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 03:16:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-726549f81a6so2121626d6.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 03:16:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVS9GJQy3Ut25Dz3drr9HnwZh92vDh8har5fhZWUhdntMW/rm7/H5AEVpTM7JI3sndIhpdlgjUAsD4=@googlegroups.com
X-Gm-Gg: ASbGncvLbYhmFwPHWDpcXjnEuowLBbGBc1W6csAxlBafl/KcJBkxl6waRg8k+yTXrxm
	O60+3TLhzs/ZO++/S25mLvCSwwpJFN1VJZAQi0M99ciQGTzU9n4MgZGy5RGbhkSSNtyFDyF7PeW
	23Z9QKt5TIULgSs0J/u8F6CUTG1xjF7KTcSZ90rPeOBvpGhWJxR/pehtww/aahOoht16ZJUvTTX
	bQEQpE0T1Ff+wYrKmrEyzccniezFZYSE3W5aF0mNJE=
X-Received: by 2002:a05:6214:1316:b0:720:4a66:d3e7 with SMTP id
 6a1803df08f44-7204a66de85mr63437046d6.26.1756894589045; Wed, 03 Sep 2025
 03:16:29 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 12:15:52 +0200
X-Gm-Features: Ac12FXymppW_352dPk8Sx6ooy74nYo3Wzf5MB3L6oworaHp6lw6JSbbxp82YL4k
Message-ID: <CAG_fn=WNHYR0J2oehz4gO8TB2HADb8qG0q++y153Jg1d2GLfYA@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 2/7] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=drOERxTP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
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

> + * kfuzztest_parse_and_relocate - validate and relocate a KFuzzTest input
> + *
> + * @input: A buffer containing the serialized input for a fuzz target.
> + * @input_size: the size in bytes of the @input buffer.
> + * @arg_ret: return pointer for the test case's input structure.
> + */
> +int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret);

Given that this function is declared in "kfuzztest: implement core
module and input processing", maybe swap the order of the two patches?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWNHYR0J2oehz4gO8TB2HADb8qG0q%2B%2By153Jg1d2GLfYA%40mail.gmail.com.
