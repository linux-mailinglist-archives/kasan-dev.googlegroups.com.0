Return-Path: <kasan-dev+bncBD6MT7EH5AARBQ65RWDAMGQETJOQR5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 53A943A43D4
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 16:10:12 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id g14-20020a5d698e0000b0290117735bd4d3sf2669684wru.13
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 07:10:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623420612; cv=pass;
        d=google.com; s=arc-20160816;
        b=wGxNKRVPElqGPUEbGi7+j6pM663d1pHxQCCcg6f0KprZCjclb1WnpPxLJ4vpfs3tZA
         UArSLzIcdZOMhblcuwlXwmi74Pej1Z+i7K+Xm2vk4XiCNd4AJIItYDdm7W3Lfys0FKT/
         hC5aiOlE02J0e1dwCyb6jKakxIzUurOzvu6axGMLmonX9BwWVAXmmasqHR8sOyiRG17r
         bAgITEJlfd2EiPegcDT9UkuOHCJWpjgeIshUdydHHdfLxG026u+rxkY5+3bMUUOCZ9s/
         ZyWQjnvlADV6vZYm0Cq51efMRcUgwuF6O3lpX054N9250XIv+dNFx0M+Yt+UXtIJa0uV
         sSLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:sender:dkim-signature;
        bh=IqNgQsZ72o+HqCYDgF/B1FVT4bnNL+fOosxKvNxf68o=;
        b=qRFn7OYuxszqpBA5CGxbqbMQizvvg6F9Buq/XrpqsKdjWrJ2PgNnPGi2m0QkWraheL
         BPtifQ7QQdUOXGEP5SXNlQVDnhLrmuem1Xysg5YNVXv1EINgVeGjNxiFqxTQZRtWyBYs
         DESppRk4SGC0IzPrBA1r/YwYK+beowFy4YsR9M7w8OAmmNPBDiF4cAWCfeCrvLVKsr8b
         FIa0ZGYZn10lHJWKR8oSl/FgCwsiBXPwbr0n/Xy7Z6NZJpaqQ8eEKKfGgySe+Kusp1KN
         uDDPM63vWdzMvwilpwmUEQlkWObcyE30lz4Hdb57yqqFLiih46V6ApD9m3IrM2zUflM1
         +QUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IqNgQsZ72o+HqCYDgF/B1FVT4bnNL+fOosxKvNxf68o=;
        b=acVfrci+w/yFxEUriW+OpTRzqeGq3d0LskbdUP8PznxNqOTzY7la9VdIrEUs7T3a4d
         82sFAUoYDWrzaEFKfi0DLJ64zbbK7rXDtEGnuaTgqgWgrhoiwXP2/8jQy5kHb9Y0tSyq
         hV+upriSf6rIH386mJS9tDZrqCMbeYzozMgxYuDxqeJiyD47yFwm3BqVCHv5ePBH+G6m
         z555jNwYOHlPJpVGAGTWjC72lRHGM48n1MNJ2VDeo2wHw1tSyJyz0hFnwSUCkKfXUxxw
         sNlxIJHAar8NpChjND/fWlhUG+ZggFNmcKy7+E+ylXIegi3Zmt673th2znOtMWZgLsQ1
         T4rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IqNgQsZ72o+HqCYDgF/B1FVT4bnNL+fOosxKvNxf68o=;
        b=alAva6yWPvD+PgwnLI3dHFMCu3xfrNOusm6zNngp1reKFAjmGdyhwTLfbq5cJrrUxX
         uwqM2SL9fLNYuANm9cWe3yc9BU30KM4XyaKy4rZWHno81gamK+4U4s57rYU7q2pWhK18
         8urw6HSBxmlqJXsw4rnjj8IUTWNxG5VFGnTXMY3aMnik0LUqJSuNqvV/88dLbZXlxhFN
         B+b6rlKIISSSiLR7NryEXhX0PznJqdpI2PTTHsTVYq8N5XE2UTAkhox4reiJB7qfTrYD
         XrELR8jo7bQdm5wIFysd7DuWqldhgakVLJTgXlbfx0uZO61f3zCdRfJ9QDe22sTAfdZ3
         SHCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VPwA9sVzzORDxZcgmGvxvX2nEiQeG3TLTj+XMzZv/ZYfnAOcL
	0uIHwPoS4vOVYIM+6LwU3jQ=
X-Google-Smtp-Source: ABdhPJwrREKVab/bZFK8pxpC3IDA99Y8TcQjQz5RYc9x7k+18JEtW4MFdHGeySI0ql2G+zZ8oSo3VQ==
X-Received: by 2002:adf:a1d2:: with SMTP id v18mr4266412wrv.280.1623420612088;
        Fri, 11 Jun 2021 07:10:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls2017427wrn.2.gmail; Fri, 11 Jun
 2021 07:10:11 -0700 (PDT)
X-Received: by 2002:a5d:4401:: with SMTP id z1mr4396822wrq.149.1623420611300;
        Fri, 11 Jun 2021 07:10:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623420611; cv=none;
        d=google.com; s=arc-20160816;
        b=zXhrhytBde2Y/muvLJA+kjzJ7QWV4elTclC/d8yzkMBenob5DiBk2o3x91lLfTV+yZ
         QoMlKgjDQFgsPR8Ge9CaCc+Ie+7ARIo9IzbV8cHJW7nOxHeZN3ixfIS2fZjdIaEsEM+5
         6e2OfKfa94fi56nR1RW+1B9umrmdrIP/JES+E8JIKPiwOHbmJa7f1fzDxGnqamutv91u
         ggVH8bwM+xuOg0FCxHYBn/brVau3zCFZzc5iJZsfU+TpZbOH9ErYusFI7vfco58NjZVu
         Mg4p/fFJogbACWYDgPeY1SqsipMrCAS4M2RnIZLTicT/2/Hiql1ozHMP6L9BgRsLZWce
         vpaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from;
        bh=XiP3sgxN7snlDC3EBPlYw28IJBYfeyhdLQUE5fBPBnw=;
        b=Z4+onQi9w2J9A9086eUdUgR9XsOHmoTAWQ8u8kLJ6oPmnSyEizCaV3E6cXbzY8HRIC
         2x0cYPVx9QY7lEZVbp8dxPOvrt2xa1ormWEVWu/383far9kolTtJe7GmsGPQ3afhq/Un
         ZOKLlIjEqtYslrgmahLBWS5YS5PFQRsBvQ/RrpmwtAsHSPoWan4WEqqIKpSUOsN2ISdq
         a44slcX3mcgQgAyNC98yNQDcErfzKkOCwv94tXMJNNcgAkCFlXXXnJit7++zUt4c4l+z
         yU/kcsrZiOk9QA3h1eVGR37GhVB4guQdDlRV5rlsaWq3ZFk62YgzywditKm6W6Pf20W4
         2b8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id f23si143433wmh.2.2021.06.11.07.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Jun 2021 07:10:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G1jR31TRzz1qt3l;
	Fri, 11 Jun 2021 16:10:07 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G1jR26D3Sz1r0ws;
	Fri, 11 Jun 2021 16:10:06 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id blSMxjRTcGUs; Fri, 11 Jun 2021 16:10:04 +0200 (CEST)
X-Auth-Info: dkbXKa2FuB4b08eUrov5kSul9UpeLtIdhCkDN2zB3p004oJgCtYlXEmO7oD1pnrg
Received: from igel.home (ppp-46-244-189-84.dynamic.mnet-online.de [46.244.189.84])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Fri, 11 Jun 2021 16:10:04 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id 01ABD2C365F; Fri, 11 Jun 2021 16:10:03 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,  Palmer Dabbelt
 <palmer@dabbelt.com>,  Albert Ou <aou@eecs.berkeley.edu>,  Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,  Alexander Potapenko <glider@google.com>,
  Andrey Konovalov <andreyknvl@gmail.com>,  Dmitry Vyukov
 <dvyukov@google.com>,  =?utf-8?B?IEJqw7ZybiBUw7ZwZWw=?= <bjorn@kernel.org>,
  Alexei
 Starovoitov <ast@kernel.org>,  Daniel Borkmann <daniel@iogearbox.net>,
  Andrii Nakryiko <andrii@kernel.org>,  Martin KaFai Lau <kafai@fb.com>,
  Song Liu <songliubraving@fb.com>,  Yonghong Song <yhs@fb.com>,  John
 Fastabend <john.fastabend@gmail.com>,  KP Singh <kpsingh@kernel.org>,
  Luke Nelson <luke.r.nels@gmail.com>,  Xi Wang <xi.wang@gmail.com>,
  linux-riscv@lists.infradead.org,  linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com,  netdev@vger.kernel.org,  bpf@vger.kernel.org
Subject: Re: [PATCH 7/9] riscv: bpf: Avoid breaking W^X
References: <20210330022144.150edc6e@xhacker>
	<20210330022521.2a904a8c@xhacker>
X-Yow: Look!!  Karl Malden!
Date: Fri, 11 Jun 2021 16:10:03 +0200
In-Reply-To: <20210330022521.2a904a8c@xhacker> (Jisheng Zhang's message of
	"Tue, 30 Mar 2021 02:25:21 +0800")
Message-ID: <87o8ccqypw.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted
 sender) smtp.mailfrom=whitebox@nefkom.net
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

On M=C3=A4r 30 2021, Jisheng Zhang wrote:

> From: Jisheng Zhang <jszhang@kernel.org>
>
> We allocate Non-executable pages, then call bpf_jit_binary_lock_ro()
> to enable executable permission after mapping them read-only. This is
> to prepare for STRICT_MODULE_RWX in following patch.

That breaks booting with
<https://github.com/openSUSE/kernel-source/blob/master/config/riscv64/defau=
lt>.

Andreas.

--=20
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint =3D 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87o8ccqypw.fsf%40igel.home.
