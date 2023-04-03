Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCFLVKQQMGQEWEMAQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id A32886D3F98
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Apr 2023 10:59:54 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id c2-20020a170903234200b001a0aecba4e1sf17317396plh.16
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Apr 2023 01:59:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680512393; cv=pass;
        d=google.com; s=arc-20160816;
        b=eahDoL44lTJ0xUlX4SG9vTu7bGBQRLZ8q527Clr8zD9shjx/gPXu2LnftnPQW1Y0vs
         iVstRzdtSp1Z4gJ76fPBX1DQLZSz2ZHHibnkwPBvNSCzlgmT4ebvmJEiZLXBvA/f0U9V
         tLTa7+tUG+ipZ5wutQV6IkOU4p2N/D1+jReIgYikFIkQvFk0iVG9/4Wlf6qp6hUK1Kl0
         uc9yncnKBqF3idREb3TjDqTEtagHsGlJGkqcCkAJDLpupvC5kr1nK/uRc92Ir0TPsroc
         u6EsNgOUri3qE5joGfPst2cP0MOzbXAyaPyht13S+jP4nbQ2R5z60EUOn0c+9gVF9ZF/
         Prsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z3paXtE/X8oRmdXjCL+y00cd57JMG6B+1+nMYDRoZU0=;
        b=J6Yn9MF+tEuS3E0b3i32fb5Rfuv4vYAUARMfn07ZPIuzh+KOkR/RBvj56cO9IaJzgJ
         Um8LY+jxbOk5Ric+dII5cVZ++/4+MYIHGD2ux6UrE/6XkT9wo/3SDViPQfj4O6f0LlvC
         DiDN8JGcfb3Cda3cBTWS12fqUVAUoOWPEskJd6SlSz2aKyHZn+olN7L8vWvLKdZLQul0
         E+xt/wU7eMUyJAAispqK47ycsHHzNpaC4YnJY1k6fN2tcEJp1mgVpxiQLQujSIaRxCQT
         1k7ar8kNyE3TzQSa+k1s6JXMKCFAVjMgHlsEAe+JdjMkmXpdTzqEB53+aF51RRXezMkj
         44gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TB7n4Sll;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680512393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z3paXtE/X8oRmdXjCL+y00cd57JMG6B+1+nMYDRoZU0=;
        b=M23RdN3AMLn05ik4191HjPUvUZaxpZkQb7p0GfP7u5A9jhR7Y9WX/c0UNcTj8bAHGD
         7gyyMWIDYuk+bLOGIr6XnZwwKfkVa6vdofGlw9GDoH9hWlgz7KtOH1ZGlROqP2re18bn
         dbCT7ACkCq0U1ItmBq6x8eA9rD12rm44YxzIno4/okIk2BgEsb+tzmbjY3dBFHJX9SDG
         rMmfKMwXlxoQweJS2izleeVvuMBcLgID4QoonFxspzDAClJWjTx//BsfCbbDFAKSNN6y
         5lbv5qIKU8pgjn2xMb/4Nvz26jdUIYWFTrxfj27fjyygs9HxVe91TS7KgbSM7DokaEZ4
         jAlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680512393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z3paXtE/X8oRmdXjCL+y00cd57JMG6B+1+nMYDRoZU0=;
        b=pt2uRF0vlwFZjblH/wMhb6GsNBwg+fRzVbQi088resvAL3ZmUVavRlRzDS1sSC+Qn3
         YzrEP69pjuWqHFvZv8HFdayWifnaNXmi5RYfJ25w01MIR6AiJmFW/gMph5iijdxGU9r8
         khoGMp3ZhjYRBjTSMG8XxsFcI5ayztdQs3otVBCMhOhKlbleEMVecnzReO0IHydX6+4C
         Gy4ZNgImCUy5wF05iwBK5RaF9sQjg/MeHUhblcfyFFn0RHgOXtZtj4/4dNqA9K6C6cnK
         S2gwE6njk+UBifTv5v7dXisho6JmmC+5jnMx6kOG1UDSVUUWwgebQ+fmxPhq+Zr9QxOs
         7qZA==
X-Gm-Message-State: AAQBX9elEwGdegyGKLs/EiiYQqOWa5IPgeN/S2iPuoqShGaBcmdYtUzi
	17IOKHFdLa0IPJSwodRoUeQ=
X-Google-Smtp-Source: AKy350YUCK3wektm33fpjdUJGOmM0I5aJOBn3q4ndX6rCspVH6lbyl7JWq43MTjQ4ZdZ0IwzraMwLQ==
X-Received: by 2002:a63:7c3:0:b0:513:a922:6087 with SMTP id 186-20020a6307c3000000b00513a9226087mr3706644pgh.8.1680512392923;
        Mon, 03 Apr 2023 01:59:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b084:b0:19c:b3c9:49d5 with SMTP id
 p4-20020a170902b08400b0019cb3c949d5ls10640673plr.6.-pod-prod-gmail; Mon, 03
 Apr 2023 01:59:52 -0700 (PDT)
X-Received: by 2002:a17:90b:2241:b0:23d:3698:8ed3 with SMTP id hk1-20020a17090b224100b0023d36988ed3mr40398637pjb.22.1680512392220;
        Mon, 03 Apr 2023 01:59:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680512392; cv=none;
        d=google.com; s=arc-20160816;
        b=W5pyeGp/dSH/ON+IlUsKYlY8iCK+PU6Hw9wear7eh7ZpoIrnxL/4k5KVJH4iAd292o
         kPLtMGRLZlSF8cEeuxpXiv0a2cBvN4DiqjsDeHwq/Cn4IJXtu9ZpiUE6FlS6WXTw+l1+
         oNwwdrNrEGQmhb2JCBYUYQAQVDUTNpjhaVnbDSRL4Hh6CwAj18nvGHI7Al8HBbrl7OFL
         yq3GWHvlGnaH60PBn7b6bJeN6zAm0Cvoj7JWDoZB6l+tZelyGUr5HLg910tTrjs4/Unr
         Bnc4WNgPu5SQGrAt8o96Z2Hotf4zgCNQwiWxB+NbayYti4tx1QzSTgZCKe5mrqgklmhm
         QQbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5zZWYuyDzpZNaRiVgD/KXahhQyG8Rw0U/M+C/mTD0fU=;
        b=xgMjUyEt+g4gcfqfhhyRP+H1cllDfIDk2hFKU6dEAydEien1BYXw8dMFwvv6Jk99ZV
         qYlb8ECDyXY9rR3mZOE1zHIHgw0QtaSQeeukAZuucDym1TBv0iJT+TUEQFNceOu4/jwy
         qc6ZSJ1Hke5hj629pm0w73aSW2CQa6rYouDC7/zoPkaaT+9uAK6Lq3ZbK77ml5T+xCHN
         UjZK5fX88VUWSyCM0086bmFrioHOj8o1XvtALPkEJaDCWenULXuLyePILqLzB2tjnAmq
         cFtm82kZ9AS6z73T3BI9o6RmFrynjxkMCgMY2Q/Go68pXTQ7c0yeIgi71IjysNt70kiM
         tJMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TB7n4Sll;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id c1-20020a17090a1d0100b0023f99147cfdsi482836pjd.3.2023.04.03.01.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Apr 2023 01:59:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id z83so33882023ybb.2
        for <kasan-dev@googlegroups.com>; Mon, 03 Apr 2023 01:59:52 -0700 (PDT)
X-Received: by 2002:a25:2d03:0:b0:b61:29e8:e93a with SMTP id
 t3-20020a252d03000000b00b6129e8e93amr35916224ybt.53.1680512391776; Mon, 03
 Apr 2023 01:59:51 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-5-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-5-songmuchun@bytedance.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Apr 2023 10:59:15 +0200
Message-ID: <CAG_fn=W+WxdRNJVmhm+UUcTxnR204CfGHcNZ2VdxmMid91Mvkw@mail.gmail.com>
Subject: Re: [PATCH 4/6] mm: kfence: remove useless check for CONFIG_KFENCE_NUM_OBJECTS
To: Muchun Song <songmuchun@bytedance.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TB7n4Sll;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b33 as
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

On Tue, Mar 28, 2023 at 11:58=E2=80=AFAM Muchun Song <songmuchun@bytedance.=
com> wrote:
>
> The CONFIG_KFENCE_NUM_OBJECTS is limited by kconfig and vary from 1 to
> 65535, so CONFIG_KFENCE_NUM_OBJECTS cannot be equabl to or smaller than

Nit: "equal"

> 0. Removing it to simplify code.
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW%2BWxdRNJVmhm%2BUUcTxnR204CfGHcNZ2VdxmMid91Mvkw%40mail.=
gmail.com.
