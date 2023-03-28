Return-Path: <kasan-dev+bncBAABBOGLROQQMGQEKJSTXAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 21F696CC015
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 15:03:53 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id e12-20020a19674c000000b004e9af173e04sf4656041lfj.14
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 06:03:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680008632; cv=pass;
        d=google.com; s=arc-20160816;
        b=04Znvz7WSV8aOazkBCw2v2bnc6aUxwmoy+AgNQrk44z+15EycvHS4uQS/OC1SxTnRu
         Uq81tYgA1sCB3m9H+DtCqHJPyeGSDXB/U+qqQH9GMEsf9K85VSzNXXfheWRnhhTFdLVU
         rkDKE9b8DOt+L4ZW3Nct8e40YurxjV0Y5Q52aoeU4TipoLv3lJQ6gjFs82ZtemiDo5b9
         o2N0CC9qkuGHNxv+9+iXvFBa3h1sc+dB31sehogY+3mYaQRSaTKySxUhKvu2qvNLgtCg
         UsJhyufjfcVl9ICCW17zaG033AEBL6WYhUZc93/y3RtHWdFVkqZ7yQ049JcKVRMVa7++
         Pu8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=YVz/kzMc+3pnmymPd+N6Zhc3yUd5P0lpQ29hz+eqU28=;
        b=WENaL6ErUIHEwXFPkf+KYA7/LN9Jow8n317HsLsDs+KgodNKgKTxd+i+lrrf6gfhyA
         bZuqeFz1XAB5Lf6HEtGdKBHavrqZJc6J2KlKXKECD/ip2ogzkgH0MYLO/j1w7FN9McS/
         SaV1Yvhp3/H2cHJTYEmRLd1EoPBdNFw/BVJM5ASk4D6AGhD5oLUUvuzUys75Qo0dLXAy
         HGqFy10+MP6y5BTTWkP0Ym+HyCX+PhxP+llO7jKp/NE2FFKocRP8cCN5May8SaqO9PCx
         5KUKtTiDDWyOaXvjLNcF7wKJu/gEfv5T3ju3fwZOUzgAwkZdR+957kFtiIACs7BSHXHw
         +tDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RAvirNNu;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::3f as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680008632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YVz/kzMc+3pnmymPd+N6Zhc3yUd5P0lpQ29hz+eqU28=;
        b=qqAvrd7AiBH+NXn/btsVR/CHLlY4/uCmYlIJOX1xZGn9STryhmoe5Neb1VGKfvcP23
         S44vSfyiZ4JV5iJT2yEiRzxThHethqn7Jbk3WyqS9MU/f0vFTiQq9SgAiX08ClCoBJIM
         pv8FkPyFVo8Mec7qbUd1u9mduJ6E+YwzRdn5LdMCpD1f5s3vtZLvGPxTc7uiAbrez8ho
         oZr05znQe3YqJ8JQD5jb3y7DrPToDKWTlz33tOyJc6Ip7mVSSdkIdw5nXMc6+nY/Azo4
         1TVOQHvgnVJfRCcJrc7asJhX4GTckfRK1b5UZ5QpQZjNvMieM1LoN/5P0G/K2KeK+aj+
         /IjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680008632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=YVz/kzMc+3pnmymPd+N6Zhc3yUd5P0lpQ29hz+eqU28=;
        b=dp/5IWrS7ivSp2s9Ul58DYw6UqCbFPj+XtMrPriPCPo595LqUJw+eax1/nlT/6h8E1
         Y6eQGwIq3F9P6bvBxU+G9l6u1WQVbeihrbJGN5eGgE196HAuBfMFxjuq+unr1NWpInD6
         xgLdl/oojX0pKyaxvq/P1Z2S/Xldi/7UH1n41HtI2ot26y+UFDdZzzKuX3jSbi7XT/c7
         7vvYQPdVX0VlRtP67/40WVKRBhAHM8ll1zXf71jjpGLTg6IqnkdVYshPr8WRL2flsykX
         76UfEDYeX1KFPI99qwCLKjN5jd7/8JpJ3yqSMzZiUI+3guLX5pvcGsxKzHmeCOELwwLN
         wqcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9f+EB2mdZWNOQwCLIwS1UUhRs10MX3XmoO67rt0u6mi98WUFinv
	my93xdSr/+oVhKLR/l/KT+8=
X-Google-Smtp-Source: AKy350bvt9tpoWZqJOYz8ZlUZRuuVE5ELlV7Z3+kOXoQlz7+1SX3tu6m7FIFojIiAuegZxX07ZgxiQ==
X-Received: by 2002:a2e:84c1:0:b0:2a5:f850:c356 with SMTP id q1-20020a2e84c1000000b002a5f850c356mr2001441ljh.2.1680008632485;
        Tue, 28 Mar 2023 06:03:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c84:b0:4e8:6261:7dc1 with SMTP id
 h4-20020a0565123c8400b004e862617dc1ls3824770lfv.2.-pod-prod-gmail; Tue, 28
 Mar 2023 06:03:51 -0700 (PDT)
X-Received: by 2002:ac2:4838:0:b0:4e2:523:4451 with SMTP id 24-20020ac24838000000b004e205234451mr4387412lft.9.1680008631390;
        Tue, 28 Mar 2023 06:03:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680008631; cv=none;
        d=google.com; s=arc-20160816;
        b=pscwCapuEvkKN+/jPWtPb5e9Bteca7ALrxNbVGalzCHwXUj1Le2Av/IvCW1Y+wWWrZ
         qu2cpMTFz21sgPzAta2kKHpRD0IfrTcY6CCt/U1UaQYHxt7tjQjAg0iwEZlera8lPvQd
         HdpcamXJCpLQa1vAiY/WSUzhU1m7f3SZOFJkgSYr4JjcCpPWNR5V8GTLHAbfmAbT344v
         N6J43p9JmScBmS1ypXBlr9H9vKp5y3j/WGgWq9/vOvJ+fIcYWZjzNOj0mAC1QblX/kVt
         SetLH/qae/2V52do1HV9d+rVvKT2PpE9rrhF/OGmowZB31YPFq7kFwCmJ8o/WsFBNdEV
         F/RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=V66ylQ1ow/PtGbySiIbSuU+rKhrjYB2OH7bPvmS2Z5E=;
        b=szAhzqbKBP4QJQjxmmO7ezU1pqPndlZN/gFu9m+1Qf95fBi54L3mQllSwYagsnvZOR
         vpRO5Yh8KDUNsOYcjC1pdGfS3VDW/nxIboZJAs6P+2tGiRqNIVPHvJF2/mr9VOU8tY8a
         8KHGxQ7opeKbluBVVHxXq0k7vo5Mw0GEDxRdo2g9ARg6/g+WBjT3NAjQM1UHJeBJslD/
         pOL7hLazXTbh0R5YYMtRv/4V7c1m7WDFQQXczZejtOln8KXgZGeDOV/weXPThaYR8TbQ
         8KXTm2dmzLSzQDSlHDVFq3zVocpbuszmNNtY40qbO77bdS/cU/imMo4QEaDap+CnNGo8
         sNaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=RAvirNNu;
       spf=pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::3f as permitted sender) smtp.mailfrom=muchun.song@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-63.mta0.migadu.com (out-63.mta0.migadu.com. [2001:41d0:1004:224b::3f])
        by gmr-mx.google.com with ESMTPS id be9-20020a056512250900b004e83bb20554si1722524lfb.3.2023.03.28.06.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 06:03:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::3f as permitted sender) client-ip=2001:41d0:1004:224b::3f;
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 2/6] mm: kfence: check kfence pool size at building time
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Muchun Song <muchun.song@linux.dev>
In-Reply-To: <CANpmjNMVOwgc6dBnrUbGimi1oAJacwYBzRfpaZ8nqQz-ApDMXg@mail.gmail.com>
Date: Tue, 28 Mar 2023 21:03:15 +0800
Cc: Muchun Song <songmuchun@bytedance.com>,
 glider@google.com,
 dvyukov@google.com,
 akpm@linux-foundation.org,
 jannh@google.com,
 sjpark@amazon.de,
 kasan-dev@googlegroups.com,
 linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <FD867635-75BE-4C87-857F-057BEB5530D1@linux.dev>
References: <20230328095807.7014-1-songmuchun@bytedance.com>
 <20230328095807.7014-3-songmuchun@bytedance.com>
 <CANpmjNMVOwgc6dBnrUbGimi1oAJacwYBzRfpaZ8nqQz-ApDMXg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: muchun.song@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=RAvirNNu;       spf=pass
 (google.com: domain of muchun.song@linux.dev designates 2001:41d0:1004:224b::3f
 as permitted sender) smtp.mailfrom=muchun.song@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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



> On Mar 28, 2023, at 18:14, Marco Elver <elver@google.com> wrote:
>=20
> On Tue, 28 Mar 2023 at 11:58, 'Muchun Song' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>=20
>> Check kfence pool size at building time to expose problem ASAP.
>>=20
>> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>> ---
>> mm/kfence/core.c | 7 +++----
>> 1 file changed, 3 insertions(+), 4 deletions(-)
>>=20
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index de62a84d4830..6781af1dfa66 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -841,10 +841,9 @@ static int kfence_init_late(void)
>>                return -ENOMEM;
>>        __kfence_pool =3D page_to_virt(pages);
>> #else
>> -       if (nr_pages > MAX_ORDER_NR_PAGES) {
>> -               pr_warn("KFENCE_NUM_OBJECTS too large for buddy allocato=
r\n");
>> -               return -EINVAL;
>> -       }
>> +       BUILD_BUG_ON_MSG(get_order(KFENCE_POOL_SIZE) > MAX_ORDER,
>> +                        "CONFIG_KFENCE_NUM_OBJECTS is too large for bud=
dy allocator");
>> +
>=20
> It's perfectly valid to want to use KFENCE with a very large pool that
> is initialized on boot, and simply sacrifice the ability to initialize
> late.

You are right. I didn=E2=80=99t realize this.

Thanks=20

>=20
> Nack.


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/FD867635-75BE-4C87-857F-057BEB5530D1%40linux.dev.
