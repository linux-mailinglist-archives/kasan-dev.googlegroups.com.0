Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRPFXOTQMGQEL2HKX7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1329178D3AF
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 09:41:59 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-3a78a29bcd9sf4846910b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 00:41:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693381317; cv=pass;
        d=google.com; s=arc-20160816;
        b=df5joRJ01+Q1o1Q7cs3+Jy5j8b8jfYkChC8yxJUkpPRwp2Is7XnuWLywou3FJShsCQ
         ljY9x4tVdXQrzPiYtbV/CxdO1OTN1AzJR7U5XJquZk03ObOgY/64e4SrxKGttLgvdK+w
         LhL9zsC7xErDuHf8qNp9Zx+Wjq6mD3ZiExjioW3dBiXuMsHrRebJFytxmb62tKDLgYFK
         3LrTkq5c8R6nC3IQdf7sNrMbWca0PYEovHCs7aqEALIXRw7KNGF3DlhNkEb23ZTl34BW
         i3N16zZbLVDvTk0zhfgmTe7WH7LOWK1vgQq9aJfH3hXjz66uBLrJw2TxDoSB//ugan5D
         XpTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PZyIhCXSDR46CHT+D5Mi343r7nExlwzOjms3+dLLRLQ=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=QdAONx3P0vFC6yVNeMSS7eCNXw3vAEySlvK6drd5auKsuYGGjIEWyrcFbq3ZqAEOtn
         swkkDR1CiEMo0sXXS6zGbK1JaVFr6bWwdRIpLA2GAhrmXKzI+F1t2u4XPb0AzYztKtFx
         7TJumy0d/j+fepVmJmxrhDC8mR2nmdTs+vYh2fyQlmUiRpheGfGNBVry/0gvRiUrXohQ
         /XrVwW6SY0h3Pq9iqqFT/gYnAAVpTW1d717c1Zfc78HzLBOPZQJub51uRH8Zd3wxyEmz
         qKdZ0cAuNVay6IVaeKw+z6mpLdarB1Jm36j0RtQZIOW+nAJ0inTVnmqf9ZIKWdPsbrZA
         bX/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=LJgnyVfL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693381317; x=1693986117; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PZyIhCXSDR46CHT+D5Mi343r7nExlwzOjms3+dLLRLQ=;
        b=KrYmFBx9nreQLZb4oXclqpBFDpOMx5ZTrQ3Kv4SOXHvCcF8Qp0eCFuWlucxFB81Sid
         C1doie/4fFQ9nG2VTWQ/K6SggiQRxGD/xdSzSnFTM72Zo4s2NTGp5JRNIMq/pO1WN1SZ
         vY5G/BCRTTNAEHNm/o/5lbhFkeekJrUOKsOnx0zuUsRO5pys9y41aV1ek8LnGGK0rt1z
         At45OgYoR0FuRm9xjg0shcvxzJMpXF//d8OWpkAsdI05bHzc1haDCYLUscCPjc6z9QuT
         87R2uN+yQhAVxat5tjz5ovrW+/JzBTj/SrdmCXQ33K4tvtTdG9LNRmL+oAdXjGI2ar8m
         8yAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693381317; x=1693986117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PZyIhCXSDR46CHT+D5Mi343r7nExlwzOjms3+dLLRLQ=;
        b=RIwS42yneBl7luN7CAyYrFD/09Il5O2+jWbPfQcLVvjqh7sdCtaoDCNkNQGf0vczf4
         BJQ+rT+xU7pkpJVC12E5GhUmbXhz1dOy8xTpmW+0xuRhF+z+mMOZcjnDujGAkTZm12Yx
         ADb5/tXZnO08SQl2u4Ydsre7hWmTm6YYDNTXSD07RmrC5i7nGgrWSCLaNzeGYz74vGYW
         kZuOHf4NpR7bIq7gSiEDsDMkcuC85EYespiBASymnJ0XTX/k+J/6nueco7u7IySKLVp7
         Tq2f7IyZpvGrhK7xQ/I+Icr6mq22YXsuK75Wqu3pSHiq6vQ2A8o0NL/RHEUR5U9BT7LQ
         bdVw==
X-Gm-Message-State: AOJu0YzvbwCAdcBPFP6gHkZ2yv9Rnk8IjwsvP0UGmooCwKNoGlB4WELf
	59KQWKeaaQvmW+EJDlJtzlg=
X-Google-Smtp-Source: AGHT+IFNPtqkQo7carXgsT1eXxcXTx3cxrvLS8e/y9eOnxRjIM3mPWZNt8SDnKg3fZmLlsLYm9oBAQ==
X-Received: by 2002:a05:6808:917:b0:3a8:3d5b:aad6 with SMTP id w23-20020a056808091700b003a83d5baad6mr1351698oih.55.1693381317640;
        Wed, 30 Aug 2023 00:41:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:23d1:b0:263:b62:446c with SMTP id
 md17-20020a17090b23d100b002630b62446cls4001124pjb.0.-pod-prod-06-us; Wed, 30
 Aug 2023 00:41:56 -0700 (PDT)
X-Received: by 2002:a05:6a21:4985:b0:148:cda5:45d0 with SMTP id ax5-20020a056a21498500b00148cda545d0mr1700439pzc.34.1693381316675;
        Wed, 30 Aug 2023 00:41:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693381316; cv=none;
        d=google.com; s=arc-20160816;
        b=Yhd7EMI4TddUWApz6sdzd8UFviqx/WujaqqQS8sMT/vdH0dLSlXQ4NnP8npE3BLhPr
         fAoo+05rrUB0ktvwhu+2QAh1Nmwau2hjRKKt7DDaLdh8130Faylj/xRWt+Mm+EmbF+V0
         0vqusajr7CYBRpf70mFbsfdcPYCzoBXs6Tl1hDobjyRH82hLlLOMqh6pb5TbvE360NO1
         UPsD8BNJj/8SmI+Gjk3uLXfsWmHVXKI4o7jqS3DrS9m0/G6DvpNbFR/0+Tnmkx0RUz0h
         Q+RLb2jawGgoI3XDLsZlKY3BzJxwq9bx3I1/I+rSt6eOvXsT4SerHZhm2VlU9Drz5G1C
         wVgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kwOnzp96+NaUMFkX4e+N6heHm1OXXvklEEOWXELjx0E=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=JPxdkeYrQkTas6TbL0wUMpa1stLLGgz/03RIf1iI5n82MQAWPAElBIbIhIwQ9b+Vr7
         wwt8Cb7DXQBXlyRD0SxPLWUSvtH+/sgxNG9itylk0EsQifYt9I+rQB7DubJ7q4DJlWCB
         QzYb8Cs0GE7MuJVP+yB5/y0uw8mewmZOTtSSVE/DjqnClh0KpW5bhzybDMx2tlaw7Qio
         LwLZ9XkRMrdgBUuoaSmmbEDlyK/gqw5y1yUdN7lqWuRj2xBFXNbvv7FSFI8/+at55skz
         uPlACZuxfTX3Ki1GdnKKA8+uyVnpxBSoyl2brrymv58B0qOgED4cqXIMJtDHmL/j793L
         +Hxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=LJgnyVfL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id u8-20020a056a00098800b0068b7f0170f4si1787581pfg.3.2023.08.30.00.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 00:41:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id ca18e2360f4ac-792975085b2so117617839f.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 00:41:56 -0700 (PDT)
X-Received: by 2002:a5e:c91a:0:b0:783:7275:9c47 with SMTP id
 z26-20020a5ec91a000000b0078372759c47mr1716516iol.7.1693381316001; Wed, 30 Aug
 2023 00:41:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <20dbc3376fccf2e7824482f56a75d6670bccd8ff.1693328501.git.andreyknvl@google.com>
In-Reply-To: <20dbc3376fccf2e7824482f56a75d6670bccd8ff.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 09:41:19 +0200
Message-ID: <CAG_fn=UB422b6KP-BLKKyCNuRORGtBWF6kY5mHHJfFQ14779DQ@mail.gmail.com>
Subject: Re: [PATCH 02/15] stackdepot: simplify __stack_depot_save
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=LJgnyVfL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as
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

On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> The retval local variable in __stack_depot_save has the union type
> handle_parts, but the function never uses anything but the union's
> handle field.
>
> Define retval simply as depot_stack_handle_t to simplify the code.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUB422b6KP-BLKKyCNuRORGtBWF6kY5mHHJfFQ14779DQ%40mail.gmai=
l.com.
