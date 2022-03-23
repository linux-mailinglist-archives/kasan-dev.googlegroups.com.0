Return-Path: <kasan-dev+bncBCA2BG6MWAHBBNU252IQMGQEA2ZHBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 620394E5A7D
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 22:12:23 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id w25-20020a0565120b1900b004489048b5d9sf1011546lfu.8
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 14:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648069943; cv=pass;
        d=google.com; s=arc-20160816;
        b=TJL1c6zhgyQEGoHMZTxPfxy6JXk57iFN+XgGy7YFZ+8G/dot7KAuK6VObZ2QelSAyA
         ZCy4VrNUXINLUh3Y5UL2dyhWfU/Pj/GNrM5pYUKHj8Lntvd4qA/a0gcoUNPWnPzDdWDY
         R00lVMMzZHSV96OuIUGst2sT7s2W2SmqFQjxgQ2rj0/rQvS5ihOVSHQYtIVQhDwyNKDp
         ypxPvHBkyQireSB023vLjpZwh2VdH/5EApIIG2U22duzosawsmR+8agbxEMPAyGefDWJ
         ylGKQJ9Ul3/+GmrQKteCocW5S6nvyZXGvnJlvhYLxBGOFtHFSzkPy+xnBhnO6IZLJ69L
         BfUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IUCdtPZBynFv38KQqz4OFNUTzrubs4r+/FD6c+3XE9E=;
        b=tRfwTfB3srxwFDaMN5zOckpqC8WbuM5bXFGSJHxqbnj/1oHOQsbKxALmUc+SOlSXY+
         Ng4Jeje5IXZ1Amkzp4f7MBxqOyQ7ce4n558Kww6myYJ/o5B0THomGpOrhp72xEQzS+t5
         eXPpTYsd/TkXzZnNmk6Mm76K7/dnRfi9vhevKdKSZxhvgide9QNFPg9AvHsBOdmh7wlO
         5/oPbJUhSZ3UP2tZK7OwWKkbXLZRbJaxPbAz76DkeKde2WwtfmZ0JnEUGcDsO/WVXI7h
         Kiv81Ze2DaQrI5MThVUVdQxhzTzy07xkwfDXbi2j/cKTpYgMLRpid8zttrmbYUzwjzB3
         QaYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KagHArbQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IUCdtPZBynFv38KQqz4OFNUTzrubs4r+/FD6c+3XE9E=;
        b=ijnU3+fbbPkVSeFXQTDkfxhA0vEQgVVQ+1OgEK9Sj3yZ2LXUCMIbG0krzj2L2bDJv9
         ViSQZ1h7F/BzUqCvOS9M8Xm+XkullooINSiW4BUQd+xM4mY4C5f+p+WnKlf0tMK9MlxQ
         CHis+V160PrP187UbkY2bdtOjuClh/dddUZ8TR3oBDtM7NxwUpqPaHweiChAVHSxLDM1
         Z7bHnwAdf7NIFSF9mxeEN9LfZEpBZ2tqcIBbWVJvMveqBYnqPeC1rEfu/MzCNPJWS3ib
         PcV9HciXD1zeGm2Qh6+urbNrh6fXBhtTV+XV/L4Gmk/7j0weFtfWudBG78zB/OH6OMnp
         EKlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IUCdtPZBynFv38KQqz4OFNUTzrubs4r+/FD6c+3XE9E=;
        b=UQ3yqv64Q1v/r09LPToyXwIE1K7spAx3Zs6SMztSwOtsYqwIxRp4zzBph8Ow4+UtXb
         4/dW3E8JDj6K6EDFruvgq0Q4x5zRPHeE6JwgJZJVful/GUZZlBbSuD/AfK71ARwpNjuY
         ecRcH78+KAY6YXn69pKCs3Wx0l7zDIsPeUkQ65zjRivp5lAuoUSZ+rN3+uf+rNPJUPSj
         HGjHVp2lEbvMWnBZhVuqMQqa888A+i80Zw8mK6Xxh+82rCBFxjM85sC0s6Kde3wpLxgY
         NnMU75j5DX8mGvpfm3VumOMkSayEBj6AfIecDs2ANAPxH2K+vAM7cIEtjBWnM9qoy7XZ
         0yOA==
X-Gm-Message-State: AOAM532a1T6LIuFBbhL2LZhfDGOjcrsNYSm8ojZfBhs9XBwRkQOVzm3M
	gzEox53FdtPa8N5uRoEFYLQ=
X-Google-Smtp-Source: ABdhPJwvXtLidcuidRYSyL12u0Iwc/7V/00BhSIy74ffxbRnPmeVi1BQRLJrj6gV8FHk9rQfnkLepA==
X-Received: by 2002:a05:6512:281f:b0:44a:5aa0:5b88 with SMTP id cf31-20020a056512281f00b0044a5aa05b88mr1354303lfb.444.1648069942780;
        Wed, 23 Mar 2022 14:12:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9983:0:b0:249:7c7a:28d8 with SMTP id w3-20020a2e9983000000b002497c7a28d8ls5149lji.3.gmail;
 Wed, 23 Mar 2022 14:12:21 -0700 (PDT)
X-Received: by 2002:a2e:8502:0:b0:247:eb12:c34a with SMTP id j2-20020a2e8502000000b00247eb12c34amr1616561lji.405.1648069941767;
        Wed, 23 Mar 2022 14:12:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648069941; cv=none;
        d=google.com; s=arc-20160816;
        b=hOqqkjlbJT9gBcjZ08rLxIEjHzi8qMq3kPa5PJGINAk4E+krefO9ooXKzs/dD+/uR6
         dU2Q1cFypIYuvnBFgbtkqQo7uwTvjXfaSH81iRyRwW/I03CTQ0ERygwvqrUd8MQHeJud
         skvyPEtGNd/wsJCqidpn5UqazZIe0F4SQRfGxL3dMFZNuZ/H8E250EUeNH3/r3n5bGGQ
         /VTI7uukWtBpegaehJ4nVPs1cqenlAmHbP58xkGhtSrhh7k8stXx5tXBhkhzq7ymMV3T
         Tv/L/MF89i6/UAHzfcJjQqTyGfc4p/ro5GtIq0ILUKnxzK+uE1tsNeC6BXMiCPwZMoNS
         FXkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7J+zvKOI6x01hl/yYGK7ZfqaUiakMK1iiu9VlloF/xA=;
        b=nC3OqS+mz+p8ZYasUSK0v+3uOdUNRmsMvdSTB0EwiCughZAyV6873XEa4/XD6+F6RY
         73x64GKforPazbkeDfMsbjxQ0dgDY8bgGJ+uAsypDYipX5TtQWAp1IZ0YiBsHaoiLbiw
         tJ4oD9RLA5DBq77EVXTa1C/Kxk0TxDIxHQq0nINMBiULdlREWyE7NsmoaJKcYldNjjbp
         cRoHdT9fo/vcUilOUqsFW5AzKRQtSzeBW9qV6zf3jZPB5yO6ZJlm+OgVBn1SqGbOlNxz
         Kr0Af/GfYT6EHZpWziyBpG2GtaE9bLjd5bntPriJgQEWkLW/7Y4jHBItygUaTyIzvMXm
         Zc+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KagHArbQ;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id c11-20020a056512238b00b0044a538b0865si64442lfv.10.2022.03.23.14.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Mar 2022 14:12:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id t1so3371754edc.3
        for <kasan-dev@googlegroups.com>; Wed, 23 Mar 2022 14:12:21 -0700 (PDT)
X-Received: by 2002:a50:d949:0:b0:418:ecfe:8c25 with SMTP id
 u9-20020a50d949000000b00418ecfe8c25mr2709073edj.156.1648069941134; Wed, 23
 Mar 2022 14:12:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220211164246.410079-1-ribalda@chromium.org> <20220211164246.410079-4-ribalda@chromium.org>
In-Reply-To: <20220211164246.410079-4-ribalda@chromium.org>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Mar 2022 17:12:09 -0400
Message-ID: <CAFd5g450=jBk51-4wMBxEA+VVQnOyxqtF5WV-J0dCW3j-eAfkg@mail.gmail.com>
Subject: Re: [PATCH v6 4/6] kasan: test: Use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, 
	Mika Westerberg <mika.westerberg@linux.intel.com>, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KagHArbQ;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Fri, Feb 11, 2022 at 11:42 AM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace PTR_EQ checks with the more idiomatic and specific NULL macros.
>
> Acked-by: Daniel Latypov <dlatypov@google.com>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g450%3DjBk51-4wMBxEA%2BVVQnOyxqtF5WV-J0dCW3j-eAfkg%40mail.gmail.com.
