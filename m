Return-Path: <kasan-dev+bncBAABBR5WVSRQMGQEALB7EZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C8F70B69C
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 09:35:37 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-518d6f87a47sf3101260a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 00:35:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684740936; cv=pass;
        d=google.com; s=arc-20160816;
        b=ecgmrBL5+614rJmIovm5Vg4ra6MKgjm2WhUo0oGPESv8TcMd/dnkRzVmpypSOgq4S+
         tuOeknsobvMrhupmdi/+1LScpHNauyEk7aHHro1uuymXWaJdcMyRs6O3KYOL8uKJHRY5
         IeUlZsUBKJZpk6qh6D2wmyWrGbVOZp8dFZIXqfxeJm7qNuaLa63GqKrjK9tdDLRs541D
         sVrOvTWCUcjCEJE5IK/O+qsHIm7crukP/PTG6GujAD4ND8c6MW2HCT/LSkQe5pu8epyZ
         m8HfHSrLquwgnfP77JBlGgWBJsJNEDk64eKpve4quW0xgJ6KXSLmLarpMAkVbLTki7hu
         ghKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=6PcbSkTcpskG00UazVgl4sQrz6BRHZgPVeVej4iwAaM=;
        b=aEbKJ/xQ6kpSmBiGlyne68JSFrfjc3GN6TN3//2Bj12aSnZf6do4ibuuvdxeQK5ncl
         ALF8gsH1Wf4MTnicm/XLsSGs9+OBYnvxxjQdFdBgcfpqh4RC0vsdi7AoGhAUZOIxo3UU
         YSwH9/nw5gs7pJrNyr6qf++hIPN08OqC0DFpfdcWfWz0W3yVlw9zMnvVmNBFw7qlwo7q
         8H7kvxefvPdO3q6g8A8Dp2mqo5tXDu8uIeGda+rpHJD4S8XTnZYvmMuXtnLTUgDYJW6M
         6c/FnqwJSLAkB5rRxbN2scxa29or6nucXR2FOa6Il8lNgtphixSV56bH2AfZVUSP702l
         +w2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684740936; x=1687332936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6PcbSkTcpskG00UazVgl4sQrz6BRHZgPVeVej4iwAaM=;
        b=ZzPljRFZIBJaMkUdxjDx1N4Z5q9rgKekRHk2SvDfuIWDl0wcwSnAKaEZbiId1GDiXt
         fR4kTC1hBnn++BSgUEoJ29NAy9kTI0E+r7keTWY+iBGlwedPOYOw3llHiZ5OISbWK6co
         BN6fX5XyDaoOP81lyJpQX3FSeGxKW+edco7JShG6xY/OCSncgGYXyjC/3/jOOgRH5SoD
         MlFXYsHz/ERhgl7nFSLFCHtgvfaZsPcGrdxWXsgl9lDa2Se7WHgpa/hiVv0dogE2vl1n
         kroADFa8UCQR8eBaVXXviUayugMcAqOtvMwhF1cmdSKQddOPj4okjgxa2h0QkBCPzhGX
         bxqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684740936; x=1687332936;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6PcbSkTcpskG00UazVgl4sQrz6BRHZgPVeVej4iwAaM=;
        b=ltOQv21lggoO//1Sxaxugi4tAaXjTK6aVOSWKqLNx2Dj+8i4DqLXelAV2myuOreIHR
         m4FS7l19Zda28bokah+2m1UjpgEwqpViSfUUz0OWhsvQzUnNOng8aHz+zSCeQAUu3OFh
         T7hCKn5ASTVJhi2SVMLoCPK7R63EJy6aAobalFi7l18/DNb6AAHJl3xSJj5kmxYFerrv
         aL37hx81V/FOEpK6O9WuhNVQy/S4mtepnynwXBvdtBKIRa/9RI8cYCKWBphN67zReN/P
         ESDIKaRqSO/xWe1WZrUvA6uFHCT8XrP0Yy9n4H3LOHVOXvVHlzthQ4vP43RSucZLssSn
         s59w==
X-Gm-Message-State: AC+VfDzVjmnfenq3TzSLfID6wHPUKMy0tWpbxjlCeqOp+10i8R782d6I
	7tAmPiUiPRN2qDveg/ffhJU=
X-Google-Smtp-Source: ACHHUZ6+dw0wGtTHPL3oxnVf6DOY5EuLDBViE1KIViO46LXs8md7Ju5M7t0NoUyvp4J6VOStIgVhFw==
X-Received: by 2002:a63:513:0:b0:52c:407a:2275 with SMTP id 19-20020a630513000000b0052c407a2275mr2243056pgf.2.1684740936074;
        Mon, 22 May 2023 00:35:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8203:0:b0:64d:3333:495b with SMTP id w3-20020a628203000000b0064d3333495bls3083930pfd.0.-pod-prod-07-us;
 Mon, 22 May 2023 00:35:35 -0700 (PDT)
X-Received: by 2002:a05:6a00:23cc:b0:63f:ffd:5360 with SMTP id g12-20020a056a0023cc00b0063f0ffd5360mr15160026pfc.21.1684740935467;
        Mon, 22 May 2023 00:35:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684740935; cv=none;
        d=google.com; s=arc-20160816;
        b=G1g2QJpjTmlapMJyN7CuwsKE2fUGGDKmeQkvauETPSCa7gfKo06AXqBfMmhhgFKJjd
         ilfwqR/S4kLjRUDjwyH4UF00DYxMgc1aQWX0Quv71453n1QS9lx3Avok3lHLyBLyWerl
         Y7oSJI+DE6XRMV3vvJwG2pWV6vazu4OEK679jlajjyWkoaAsatwuV4BcRhm5j+f/6bMy
         CJkKpBTbbpfOPyIAlhQb21Byi9XOUK4J+mAkZQIAzmElZNdBP33Rwpe6Q/m7tGgGll+Y
         izGXRxvquWWVN7YdJkVS0DmX0aHOog5Le46u2EUm1j2wjUgzdCBUSulhEMKuQQ+iaCMb
         EJGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=+zyMHySpPh8XlgELXOlw+871ujfaZvOUK/GYK0H4SM4=;
        b=DUE6DrGbDWD7kEMpiseqTTrsL+CWFF+cZkC+cjIK0uwFutoaoiO98vqqwBjMghg0Mb
         peyu04nVdIDJnvsaucuqbB0cvIujvyA4+/ilk7ijq2VyiXGLl5crpfw5qJjaOvvJIFDx
         bgudoP0JLcEFZjRboTKVXx1G9lQWKT56Rn+Cq1iP36+LLKmM7BxsYvNIhxmhyXhLJX7p
         X93Bqb6gUSN7lVIHyZH7AvHlSemDnARUQmcnB48BNysnEHZVTo8fOdw4LoUQQQhpVn1F
         Xn1pS5gEqj21irIJlMRbc/ITTintwU3IOn5eO3Xpp7vhCY6Hj9MaYATicE2sTpbYlo7W
         kJUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id x18-20020a631712000000b0052875a200fcsi344418pgl.2.2023.05.22.00.35.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 May 2023 00:35:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.56])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4QPpyN5MqDz18LZm;
	Mon, 22 May 2023 15:30:36 +0800 (CST)
Received: from [10.67.110.48] (10.67.110.48) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 22 May
 2023 15:35:03 +0800
Message-ID: <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
Date: Mon, 22 May 2023 15:35:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-hardening@vger.kernel.org>, Alexander Lobakin
	<aleksander.lobakin@intel.com>, <kasan-dev@googlegroups.com>, Wang Weiyang
	<wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, Vlastimil
 Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, David Rientjes
	<rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, Pekka
 Enberg <penberg@kernel.org>, Kees Cook <keescook@chromium.org>, Paul Moore
	<paul@paul-moore.com>, James Morris <jmorris@namei.org>, "Serge E. Hallyn"
	<serge@hallyn.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, "GONG,
 Ruiqi" <gongruiqi@huaweicloud.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
 <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
From: "'Gong Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.67.110.48]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.255 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Gong Ruiqi <gongruiqi1@huawei.com>
Reply-To: Gong Ruiqi <gongruiqi1@huawei.com>
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



On 2023/05/17 6:35, Hyeonggon Yoo wrote:
> [Resending this email after noticing I did not reply-to-all]
>=20
> On Fri, May 12, 2023 at 7:11=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.com=
> wrote:
>>

[...]

>=20
>>>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
>>>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
>>>> +#else
>>>> +# define SLAB_RANDOMSLAB       0
>>>> +#endif
>=20
> There is already the SLAB_KMALLOC flag that indicates if a cache is a
> kmalloc cache. I think that would be enough for preventing merging
> kmalloc caches?

After digging into the code of slab merging (e.g. slab_unmergeable(),
find_mergeable(), SLAB_NEVER_MERGE, SLAB_MERGE_SAME etc), I haven't
found an existing mechanism that prevents normal kmalloc caches with
SLAB_KMALLOC from being merged with other slab caches. Maybe I missed
something?

While SLAB_RANDOMSLAB, unlike SLAB_KMALLOC, is added into
SLAB_NEVER_MERGE, which explicitly indicates the no-merge policy.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/19707cc6-fa5e-9835-f709-bc8568e4c9cd%40huawei.com.
