Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBWMKSCRQMGQE6UVCD4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DEA3705AA4
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 00:36:11 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-54f89215b64sf5874eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 15:36:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684276570; cv=pass;
        d=google.com; s=arc-20160816;
        b=UD6nc7pkbGUfF3FxtBHftM1wWHkkpqAzFKGP4UWVhF+yzVGq3K/aL+ixHbNNZC2Jc9
         mESrP3FYlmHG1kOQtLM3uFQnCHI7Qu2NOYfdmj8LoS9uvqr65YMzr36kxP+5wIpaQxyv
         nNhiTtfMk4/sjCMvrJZDwTGHriDCEmlcXq3EjseHfycQdvTKNh5bAgLdhSozLtTfgrVJ
         Dx6YGRjhtvSQk8O9VzwpYXpR832CS1TIPweXKxWDUULfq+fH5lrmjvxKn2qF52aoGg0i
         ODll7aneDHra1cz0aS/abmd3etX2teo4rw5hOZDfH7qCgRFb/TenvKqHVqINwtCviuKs
         LKgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=12rORobloCbKs+utxDOBYqCdYoEwLR69h2lB7mU4jA0=;
        b=ZHMteXubl9klNl/I2sqlKE0w3ANL6PZDygSZV5+k8q8E2iR3K8SU96J5zW32ST1Y9H
         XRT5LdM5VL6cjurk2umfDCOfx1neQPI4+kVpj3L3eYvIWs4oq2/XcbRTW6FPVRVQrwWS
         gJDHzA/BuMN2Nczqb0w7YaahXODWmu7ZZ4M3plMGVX94Sz/9p1w6HMsWhXk+C2upHNkz
         rFBHEJ8bIcGOvWKJnlnBaroAkWumeUZ9WbHQRELD73U+Vt4M2YVHFw5TgzygkTjmrzKA
         5tsApPDf1zJ++nXfNZGNTSk5ecWtwltfQd//JIH7AUxMsy3mV7gOa4M5ihNCcPBnbQIa
         1GNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hHu4z1Gz;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684276570; x=1686868570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=12rORobloCbKs+utxDOBYqCdYoEwLR69h2lB7mU4jA0=;
        b=LKfHUTV50kIuzVKYMPEumRdO8T/1mOjaImUzABhdfZP6FFz+75nYsDtAtaVZSPOsec
         4cWhrOifwc2DEOBIkGTzmYKKBykbsRyjQFAGSlf5pawRYj0IxwNReH+gBzWlhr+ExGr9
         3p5vBkY4l6aeNJESBLZvqw/YAEKReLagxCaFehGXOvi4rGdK8NUq3+KYg4d7KsL253pN
         /PN4Z/NZkiDjxiyvLmcmuPSf620w3cXRbLm9co1L3Gp3RYopLjdVmSs1HT1Bm5sspaTS
         rU/E4jR2nfFgUAxeuJl0Tj6wH1GA1HCaX5VeuWL9HLPJE7LO+3sCpFmL2nxgCK4vAlCc
         L+DQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1684276570; x=1686868570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=12rORobloCbKs+utxDOBYqCdYoEwLR69h2lB7mU4jA0=;
        b=smzVAKGUbNp+7DuwVL19nstg7Q9qdY8HXt1hL10WmPIVqs1bCkZD4M89d17MYUo7wP
         8M2ZlQ9ML7kDF8XOTh203Pbh11QygPNg3QnEGXND/oe0th8KCRf0i1ZsbIKVf6PQfCU9
         m0mXbxC1rRdm4UEazEpqg8OEmxK+ZZ35Btl2AVM1aWMzWQtvfkGzY0Bl+VI2R6gbItOg
         OHtlZ2DsscUzXjZpOTt6gCSGI5oLxbEAnVhsrZZ2lmd8TpAkNmgiNGqE80sJLVcDYJ7J
         YBnRPePfboMyPllQ8la45n0XOmY02XLHSHb6Guc0aV0EB8j594GmPBzLcOMjzbvX4JPI
         7kfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684276570; x=1686868570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=12rORobloCbKs+utxDOBYqCdYoEwLR69h2lB7mU4jA0=;
        b=Uo3S4oivrcwd1mcAD17N0GPfsQtTzhnvLJujlvVyNTXbvjMy8JfHy+GKBYuvBwSkPK
         +wme60BFruQrHMCogsbM6yk/4sZRG6w7G9s848mPoe/l7wkoxb8PUTYjRI3bsEWsJ7CX
         WX+H/+RUGkVUb8y14wEpv0Sz5t47G8QUguoySdghbqDgc+y3dd4HdLl7oyuJfPywHWKG
         +sgXYa2t0oQ/3Ll8kTA8JYBR9cONQhQ+eJ0BOtzu0WUVyYnXktCDAdTLuTckyXeyWWS3
         QA37cuxqAiDk656sWTJRDGcnoeekVxLlx0GVz79EpQq1d23UwPm9h38XWUkKMwemFlDG
         9rig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxtyjZsw3N7CG9l6Q7n/NdeonNyAqjgklMNKR4SeCsL9BZoAYlT
	yhwU+x2leV9+oNaILbX0cPI=
X-Google-Smtp-Source: ACHHUZ6kVIgYenwt0ywp0jcGNa7y4i1Soe1qSF2VlePfM2clTgsrXYW0fjTZ7hyTuoj1RpAn6DsTQQ==
X-Received: by 2002:aca:d785:0:b0:38e:d835:8cf0 with SMTP id o127-20020acad785000000b0038ed8358cf0mr6413285oig.9.1684276569882;
        Tue, 16 May 2023 15:36:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5b16:b0:192:550f:9c2e with SMTP id
 ds22-20020a0568705b1600b00192550f9c2els368163oab.1.-pod-prod-05-us; Tue, 16
 May 2023 15:36:09 -0700 (PDT)
X-Received: by 2002:a05:6808:188f:b0:394:69ae:844 with SMTP id bi15-20020a056808188f00b0039469ae0844mr10107609oib.24.1684276569371;
        Tue, 16 May 2023 15:36:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684276569; cv=none;
        d=google.com; s=arc-20160816;
        b=U0WOd4kLrcc+brVwHl8QMdH26xyEu4oYmeJzTa6vPE2UeciBaC/zkXrKR+H9wLeNmJ
         CEQnzPplzaHJKA0PtSAftDq7mUJVEdmzfvpBYZDPbRvMCGkFP3uXLg6R5PM1C7qamWWD
         0mObwWMxaIcEaPUWzJd+ru1xeApyXbh7gG5/xUVmKKg2FZOFhn7AWn00Mp3SvHsy+oUb
         s7dO1E2lgogIkqehiNgGDKA2onwU6FlQ3Emhi3uqOT915+y/PZnWmtxfFEym2m3/0xoN
         g9Hgf5mQuC4EsmxGsA26hfjp9l2KwYerCthnuD2O9Jij8qpfPhTBDbA0dcTimtmjSFCJ
         o1HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MO6goYlwL4iToGOjsZHzqUARbwpLkTb6qhA2YqxeeVE=;
        b=Qtwg6IC2KDCSlMb5w1FZzN1GvEEPWo1NKFzdW8vLKDC4+4uCEXnj2NT5UlvqCbQGfu
         KrWrpBafEIRpPHAr4N8KDdyvE5i4AR9KJPmJG7V/vsI6h58THZXBEJtAHu1uxdxW4uN/
         AxWn2ZiMIfKXjGjpd7GZmgaLbEQWr6rJPeh21NwshWNIHZTPIyRsKtRqLTPQRh6p+y9o
         Dbil8BNyPOpsiBp1oAD8ZcDLmKZr9hd9ON4h0gh4bXRvxsmjorZ5heedl3YBXE8SOdcu
         WeayvyLKTdPUQ0o99ANOYovhPU/4LUcmwMA1cALQlOiSff3TGMVFrlnwughnaF6+pQga
         ziDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=hHu4z1Gz;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id q36-20020a056808202400b0038e4d42b941si1191450oiw.1.2023.05.16.15.36.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 15:36:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-44fd6c24d5aso70204e0c.3
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 15:36:09 -0700 (PDT)
X-Received: by 2002:a67:f30d:0:b0:436:3238:bd1 with SMTP id
 p13-20020a67f30d000000b0043632380bd1mr7960550vsf.34.1684276568666; Tue, 16
 May 2023 15:36:08 -0700 (PDT)
MIME-Version: 1.0
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com> <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
In-Reply-To: <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 17 May 2023 07:35:57 +0900
Message-ID: <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
To: Gong Ruiqi <gongruiqi1@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Alexander Lobakin <aleksander.lobakin@intel.com>, kasan-dev@googlegroups.com, 
	Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=hHu4z1Gz;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

[Resending this email after noticing I did not reply-to-all]

On Fri, May 12, 2023 at 7:11=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.com> =
wrote:
>
>
>
> On 2023/05/11 2:43, Hyeonggon Yoo wrote:
> > I dont think adding a hardening feature by sacrificing one digit
> > percent performance
> > (and additional complexity) is worth. Heap spraying can only occur
> > when the kernel contains
> > security vulnerabilities, and if there is no known ways of performing
> > such an attack,
> > then we would simply be paying a consistent cost.
> >
> > Any opinions from hardening folks?
>
> I did a more throughout performance test on the same machine in the same
> way, and here are the results:
>
>               sched/  sched/  syscall/       mem/         mem/
>            messaging    pipe     basic     memcpy       memset
> control1       0.019   5.459     0.733  15.258789    51.398026
> control2       0.019   5.439     0.730  16.009221    48.828125
> control3       0.019   5.282     0.735  16.009221    48.828125
> control_avg    0.019   5.393     0.733  15.759077    49.684759
>
> exp1           0.019   5.374     0.741  15.500992    46.502976
> exp2           0.019   5.440     0.746  16.276042    51.398026
> exp3           0.019   5.242     0.752  15.258789    51.398026
> exp_avg        0.019   5.352     0.746  15.678608    49.766343
>
> I believe the results show only minor differences and normal
> fluctuation, and no substantial performance degradation.
>
> As Pedro points out in his reply, unfortunately there are always
> security vulnerabilities in the kernel, which is a fact that we have to
> admit. Having a useful mitigation mechanism at the expense of a little
> performance loss would be, in my opinion, quite a good deal in many
> circumstances. And people can still choose not to have it by setting the
> config to n.

Okay, now I don't think I need to tackle it from a performance
perspective anymore, at least it looks like a good tradeoff.

I had few design level concerns (i.e. in ARM64 instructions are 4-byte
aligned) before switching to hash_64(^ random sequence), but looks
good to me now.

> >> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> >> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
> >> +#else
> >> +# define SLAB_RANDOMSLAB       0
> >> +#endif

There is already the SLAB_KMALLOC flag that indicates if a cache is a
kmalloc cache. I think that would be enough for preventing merging
kmalloc caches?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg%40mail.gm=
ail.com.
