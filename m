Return-Path: <kasan-dev+bncBDW2JDUY5AORB66YQ6UAMGQED2V252Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 0539C79EFDB
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:08:13 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1c318359b3fsf37355ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:08:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694624891; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZVrTbLPhYNRH00E4NnnU23bN7CDlJ9nAUytYiPpyYU/Iqmq+rHkyiVCKXYeUUPeRdr
         7+cX32SW8p0Ys5Ik6LPpTH5fmsaen71o6uLc9/ztu4U8oCcNOvFK5rCc14dyNkIJ0oVM
         d47k6EiHW7oPlibdLiyRE+vgZUa/sp7GFej5gf9klqP8Z7wXOvmqqH0sTI6onbE5klHa
         wItUf64A1Fi8dVcBmjU/7tedXRB13LcGdkXa4AxR97fgP8YNBgfkaD4n88nnza/yZDfz
         ik42xVDW2CKwe+enS8wfv6hxKuB/1TvzDQmjFbyQ72V8SrOW3ktcYd8A+aRlU+6S+JuJ
         RgsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6PYygAHPrutXK58yapjo/eNjEkyNE6N3kTOC8EU5iVI=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=kF1ZaY+ruqbcdoqoba/kAwSph60TJK/e4mMh66yOjD9wNAzeq+mkGpUPlqxXVajjI7
         QYU/f4wIRQZImiHk/yBRbPHtiPQsw8d49WK3rElt915oE5Vgc4AkMFfMSiqy66mi9wDm
         AU6p1IADB0N7VQ9lWpZEiXWaXlD0EqUP/Iy6rML+lPtnBJTNFoilTfYnqYQbeb4BB5Vc
         BqtdyF8DNeGm2pZoKmLNWjR7TyhgDFcyny268lZsrMPPHdZ7ZQoKxE1Nq5Y4QgA9IUAE
         KfOpAq8WlnejAe+e1bAlpjRBf2+PD2J1Lru7cwS9c4vt9ShaqjYzVmSNKFh47TDPOgbC
         Ecfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=plg8A1fb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694624891; x=1695229691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6PYygAHPrutXK58yapjo/eNjEkyNE6N3kTOC8EU5iVI=;
        b=acs7M/uf2kc1BLMKMEl65xFrtX0mbPde9E4Efe/w6lDENLoZk8JIiiuVzFIfAp1+vo
         GY2p8DhRQtREZzP0V0y6LpoKxsPjlSeijsSa11P8LEQ/RRXz6FRDDrVjkB6NMJJqrVzi
         y7fOU3yO9+3BvTK6xPsc9bisXosMwQ4y7SEjMeg8Rp54084nfG+z5PaaA9igqnZfGszl
         dCPecxuzDYYqAJpduEIAj40lpdMLX/yFEpZwWtmIPoednuJM92g//Cs2nvV1mEtqgtn8
         0e/V8W06BNMKvMtUUalRBmj378D7ixQBqeDNvb9ll+UlbAhOJT4R06Fn7XMKSmTIXi6p
         H4Gw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694624891; x=1695229691; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6PYygAHPrutXK58yapjo/eNjEkyNE6N3kTOC8EU5iVI=;
        b=WHN7p2uaNcvph6mIsXeZ89Cocp3wgTLTWz1GJsUGjpDTc0dpV/CFXTjZp6XNwq4R9H
         ycQzfzwMMY7KTJhYC0N11CMcv6so+rbhNOT7Xk78EXuaIwsQLh25QoorQoE/zzjyy+vh
         Cp4Ufp05/EMZX20zIj1AhWjVgBk+CymA2MZIxoY08Z1sHivoGSmtw/hljVL4ANFd2hAl
         UVxRHTkXrjh0AlVEzXH9FYLXamD2+CJx+r87Sh26DpT1JTXJf48hM5FfMTh2hvoS+pTP
         YI4dN7L1xW++aLVApuGCo+sDUm7F1m/3H0unTS6AmXGhHEuFhP2tSeVN4HilqP8F3Ggn
         7AUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694624891; x=1695229691;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6PYygAHPrutXK58yapjo/eNjEkyNE6N3kTOC8EU5iVI=;
        b=VmKNyw4XN3JYIcURE6P2EZMS8M46qjeQYQOSWSF2ObarZXRGWkisqZoV4RehZExmwP
         WadYDBv/HAJSeFmsikO4BAbq0YX2DwiGt8kZT8UyG1P8IaZ+aVmWdV22iUi2fEZIWroc
         dhK3urhyVvaO2U8a40JJZSTMS8ph0+tRbJiTPzgoqG5P2MGlk6ZfFD7nMQxDj0VdWchs
         9RHhzF3l7aFEKuY9NfF/4PwxqhzRxYZG7L/wVHa45Ji0kAnyYnZYHHRAYcv1HVeEBeqw
         Mz+raHCitSg9gAkKX6Yywl4aw7pfqLI+HRskiuMkiG4A7APrsBm2eBa94tS958vNpOTO
         wQAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxPtWKGDrYpd/eZBSBrQVRFmb0teAEvekKmY1rBAQtJu7Ggdrj1
	iJHhPgfMohcxjBbkFJb98HE=
X-Google-Smtp-Source: AGHT+IEt4yMh/1swnl3Alg8wpFjkdj01OfQ/C53svPwIjfHLoDANGJ1ztr3GVLz058gbf7RNKEo4XA==
X-Received: by 2002:a17:902:ce8c:b0:1bd:9c78:8031 with SMTP id f12-20020a170902ce8c00b001bd9c788031mr214891plg.9.1694624891348;
        Wed, 13 Sep 2023 10:08:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3652:b0:268:f76:e134 with SMTP id
 nh18-20020a17090b365200b002680f76e134ls618289pjb.0.-pod-prod-00-us; Wed, 13
 Sep 2023 10:08:10 -0700 (PDT)
X-Received: by 2002:a17:90a:5892:b0:26b:494f:ae5d with SMTP id j18-20020a17090a589200b0026b494fae5dmr8791043pji.1.1694624890374;
        Wed, 13 Sep 2023 10:08:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694624890; cv=none;
        d=google.com; s=arc-20160816;
        b=m/vwD3VP0Ni64qNB5jDfZuq3h26mBHhq4uzEh5PPiArRNWCv8zEzJd0wvRhGwOXY1r
         vlkF8ZPbcrlg+BwADj13SKchiY2iCyrdPw+KTvkmNQwO7+HzVy6qQr7/qhOah06vNvV1
         qaENCAYYcPdJQWImJgxPp6gVizMjaTNndeiNNBgklZTKqlH9HqabNeZtNY/YkuA9DTYK
         1d4qAI56TDGhqU0dmGBNprlvWMfdUA+tlzzwkIxiFjO03s9/lG6HXUahJwo576ieRfhs
         I5YD2Y1/ehQmRV6L78/+ZqGvRYcU5wOHzdg19zvEEqw5X3a9RT+bYmwGLrN9xnJpnNz7
         W01g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DHCrlCbtcAKHLlsdLR6+YB7uDJrcT7OxjXdj9zb8nHQ=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=WYW/oAdVm2vKNGgzjGhAiLil1BAceaNilUHtaTbFF8dxpVFztSODzbGtJOF19s3zbZ
         l2m9lJehP5W8sUCCj479aC8tMdSGKmvZ2JrExdUoT6QIpmIx8beGw8Nqu0/CVOETD+lJ
         Dp+lJygngdcPIiUETU3yZq3vd89rsLM+H1BO4S1KmOCVybkIqCuBqsj5Biq5zxSltTQU
         TtgFNe2uaUIXFSxmTVeI0b7K8VqjR2u4Hc6Ac/7gkxwDo03YIZSbR0MZ0v/9PkahYaj7
         nFwntuAJm1YvtbQqcvlQoMZr3a38NMrsMevfFUHCj0pBZ+25pioIMg2CSk9eXAa/sJf9
         eFyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=plg8A1fb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id x5-20020a17090a8a8500b0026b1cd2537csi226541pjn.1.2023.09.13.10.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:08:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-5657add1073so82026a12.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:08:10 -0700 (PDT)
X-Received: by 2002:a17:90b:38c1:b0:26b:455b:8d61 with SMTP id
 nn1-20020a17090b38c100b0026b455b8d61mr8465654pjb.22.1694624889940; Wed, 13
 Sep 2023 10:08:09 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <306aeddcd3c01f432d308043c382669e5f63b395.1693328501.git.andreyknvl@google.com>
 <ZO8MxUqcL1dnykcl@elver.google.com> <CA+fCnZe2ZRQe+xt9A7suXrYW8Sb7WGD+oJJVWz6Co-KGYghZLw@mail.gmail.com>
 <CANpmjNPYNTTfBAay4J96hm=3tb4kUBH2OwpaCfJxL7rP=aibJA@mail.gmail.com>
In-Reply-To: <CANpmjNPYNTTfBAay4J96hm=3tb4kUBH2OwpaCfJxL7rP=aibJA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:07:58 +0200
Message-ID: <CA+fCnZcmFsXNQobD2WGd-CXWA5_3mxTm3C4O79AWz5A8nxHOFg@mail.gmail.com>
Subject: Re: [PATCH 12/15] stackdepot: add refcount for records
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=plg8A1fb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 4, 2023 at 8:56=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> > WDYT about adding a new flavor of stack_depot_save called
> > stack_depot_save_get that would increment the refcount? And renaming
> > stack_depot_evict to stack_depot_put.
>
> If there are no other uses of stack_depot_get(), which seems likely,
> just stack_depot_save_get() seems ok.

Ok, I will implement a similar approach in v2: add another flag to
__stack_depot_save to avoid multiplying API functions.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcmFsXNQobD2WGd-CXWA5_3mxTm3C4O79AWz5A8nxHOFg%40mail.gmai=
l.com.
