Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBU6DVSRQMGQEU3NRMLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C87170B740
	for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 10:03:33 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1ae79528ad4sf19384255ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 01:03:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684742611; cv=pass;
        d=google.com; s=arc-20160816;
        b=S0dacdi629rtuzSttGeUBQHpM2NtK8cCJn1DxXbagQ+yo/BTpp4up+IINK6gNnQZTm
         j/+S8TinE8urVq2KzjPQ4apWaGGir1tbr+lXF5c2WYRgV5xALU26qpntc3lpZO+jJj7q
         p6Zo13ipomKr6/hkhzCreuFK9Q7pFdOIomBmrRlV26BWZlmNtaAJytarVNDhG5vBFbCk
         prmN7BdbuMIB9NeEPmQc2GmjhlZNJb7U+ol+pcIclsZexMkhMaGcFbSRHV+I/SWHDxvO
         LEu24JpThJ0KmFfHDfOYjftYkJviwxAsxs4Fht/CMYSiNaEYQe73A3QRXHwi/mZHoU7q
         ow/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Yyr2f04oIWKo6DydNrz1pWvVe4v+6g0oDM4Xg5QbVuY=;
        b=Ht32vHJhdRhaA+iCVlHu7JelcZ6+6AY85HewFi4Hsmvtg0gm9gXPnooHgVB4Kf9VWW
         T9DQ7OnmjSxce6gbsJ4wTtrHqRRK+AkhX22zP7Rl+Vfk9/vaAE5kd7fn9SziEhf1/9DP
         ylELCdYYsP6X/1SUYadARZJITrO+ve9jiS9nyUEGx6T+GZFUvPApv9QS8RWd8IYF3LxN
         xxGxERtq+1lyWcNqWiCFGUQRmO7mgYIs9vQnuZVt75E//gF7ENZTzFzpXbd72j0iqQip
         ABZB2K8+9ZjsfktHe+p91cqY8JopcDl7vIyaLm1vt9AL6DBSkC/M3ZmvqXH4NEfTZVr4
         IsAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=QK9rPLNa;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684742611; x=1687334611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Yyr2f04oIWKo6DydNrz1pWvVe4v+6g0oDM4Xg5QbVuY=;
        b=C1pJeCL/7/ykWbpZdpLfjL0wGQmNeurVoVLzsCqD6q9vE66kpUnRgmO43xqOfW2m9q
         L0ODj0mmCDv9Tb1pzVTDZChXHCA20zg+cjx3lW2GXml/ApJX7VLG5mzyTEHDUlAWQuWz
         fldvI/xiBLe7LSwmTKqUQDJLvLZgRpEjDnYcWIuEKO0bJSfxt+rKJfEGGSB93SMw7QzX
         Dtlgoc0pcDi3svRSXWn4iQRZpIrNGzvGHvsbIS2+NF1eI2tP8rop46aQFomrg6AoGnPA
         v8k0pn8G9fmgn5u4KO2WtCEVxXUoIPKoEdtRNFoPvyG+L4zaM1kZuOgVtEI6qUj/rsjN
         QnFQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1684742611; x=1687334611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yyr2f04oIWKo6DydNrz1pWvVe4v+6g0oDM4Xg5QbVuY=;
        b=HThhZSl+J8AknYOzJwzt/oYIae0nOY9ArMxG9NNv/PLCEIZvKnMx/uI+LLAwuVSbJ7
         wd78F58vh+L3O31ZCD93vICedEktDAPaEcdJw6xAYpKj2hZqGgCdX643l/mkF8L1uysV
         npUIdV3AWFiLyqTbd5hbbTe9omNvUKT7zmVUS2/rdKOOzqQoosoAbhJOTUgmBuA228AR
         yU8fUAZnOLhoFCpCf/5jqk4F12vWbykf+kCwbhYpI4GU5EyWiSRngDSeV0n9cgio54/O
         rrasy8VEUYjX4VIzUv08pXOfb/qGzLUo3/r8Qb0ieoEQYuEz4ZatZhyFBVQ8N911TTmC
         CvHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684742611; x=1687334611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Yyr2f04oIWKo6DydNrz1pWvVe4v+6g0oDM4Xg5QbVuY=;
        b=SYfyP9XD7poX0R7bJjsT4ea1E3By9dIuF+BvHbutAlKf75M2tPQ5f4sLszn7stntos
         COw9vdpndu8U1mFHKTSHgSMH6IfOnI6+qEsmPAPS698P06dc9h1o/3TbFN9p0mXVhDrw
         OU2FOx6AjtBhKMcbL347pW6QlPjdjGQ8NH6P1v1w3kaPx8Hf32zZSUi/uZSjfXLdcYyN
         b2aUaXk928NIHqxgp55ms0BKGrztSE13kPpwFCjFf1jR+chemtRbnuRwNziAcqbxBS4I
         BEnqNKTXtcA/kxmNznJqTvfJ36oZpqnnapnqj+jjmEdQdr1KFjf8BtK9vfggtpZYVKqR
         HAxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDytkIKVW0MtTAl/qXQ48JP5ltLlNgXXMxHBttPwbNZbpaOwd/47
	fDq4Pv0Kn+FnHNi6musVG6+C/g==
X-Google-Smtp-Source: ACHHUZ4b2TOYp4BnlBl2FwWp8chm1FxVxZicrUnEIUOmD+dUgjrWbX2eulmB1qcys5ViEZK1VDPZnA==
X-Received: by 2002:a17:902:ca14:b0:1ae:50cc:457 with SMTP id w20-20020a170902ca1400b001ae50cc0457mr2173789pld.10.1684742611640;
        Mon, 22 May 2023 01:03:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c47:b0:250:af56:cc86 with SMTP id
 np7-20020a17090b4c4700b00250af56cc86ls11159331pjb.1.-pod-prod-03-us; Mon, 22
 May 2023 01:03:30 -0700 (PDT)
X-Received: by 2002:a17:90b:3597:b0:24e:3452:5115 with SMTP id mm23-20020a17090b359700b0024e34525115mr9352654pjb.37.1684742610786;
        Mon, 22 May 2023 01:03:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684742610; cv=none;
        d=google.com; s=arc-20160816;
        b=QIX5HfU1U/K8/gWMhlSv5LiWlrtSDaGoH34poCPQxhBbZEjC6/ZU8aXlpoNPu0oobI
         8GnA9eyKZILzG7gGZK9ug0UeKlnkYQN7gtysj3sumJqasRTfn0VKPEXowLZoGI+rnDbZ
         OMjg+PH1j/x7T1XBR1CuaYRryYnx8kGnLKcqgP66uDtvEFmwyEEC8l2DHjcs+pHJo+UW
         4EHq4+9Afz8W7y7dmm/ZDyMYeLtOMED1Tii9aUMkaTMWhxVGGK/UKYbdmKq/chtMLG2s
         qy9uC0bVeEYq6skl6MakmXeSAy3XGm+PCN/wDGCO7+UZQmFWq8tdjVruqddD7k4rLzBB
         jn7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5/deT6NIs/fCmfBK6TadeTF6djYRsWDmBLQzhkm7Whg=;
        b=MUBfZvflpr+2l4b4BBSQDjaqYoy3TBFTDxo7SYnZlQBs5r92f6+F/0QXoga0zCPV82
         Pt+UxKQmi+Umm73z7JXzhX0BXrkfT6TDuQ0aJiEzXqLbe5gMySkXsc9ABnhVLpglm/ol
         meiMOvzM4HAduljmLlp2Goobi3ZS/4RNFQJb0YhntXc7EXIO/IY3qMgQ6pJk1ODgxelJ
         Zj1SvrpXbqhIaRiG8OfjKhtWejheufQuePBMlhCBWf3GPI8ubrLK451VOFeR0NRP7FM9
         bdhKXgd8mXTKf9C5sjjoLe+m3XfKXhbzEdr3zRroxDhUIjE+La0Fio1WDkUgdBOVrKS0
         sz0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=QK9rPLNa;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::929 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x929.google.com (mail-ua1-x929.google.com. [2607:f8b0:4864:20::929])
        by gmr-mx.google.com with ESMTPS id p2-20020a17090a748200b00253723d7dfcsi566756pjk.0.2023.05.22.01.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 01:03:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::929 as permitted sender) client-ip=2607:f8b0:4864:20::929;
Received: by mail-ua1-x929.google.com with SMTP id a1e0cc1a2514c-783e5f8717aso1832344241.2
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 01:03:30 -0700 (PDT)
X-Received: by 2002:a67:fe17:0:b0:439:e3f:9d6 with SMTP id l23-20020a67fe17000000b004390e3f09d6mr2336475vsr.17.1684742609589;
 Mon, 22 May 2023 01:03:29 -0700 (PDT)
MIME-Version: 1.0
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com> <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
 <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
In-Reply-To: <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Mon, 22 May 2023 17:03:37 +0900
Message-ID: <CAB=+i9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1+_Q@mail.gmail.com>
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
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, "GONG, Ruiqi" <gongruiqi@huaweicloud.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=QK9rPLNa;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::929
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

On Mon, May 22, 2023 at 4:35=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.com> =
wrote:
> On 2023/05/17 6:35, Hyeonggon Yoo wrote:
[...]
> >>>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> >>>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
> >>>> +#else
> >>>> +# define SLAB_RANDOMSLAB       0
> >>>> +#endif
> >
> > There is already the SLAB_KMALLOC flag that indicates if a cache is a
> > kmalloc cache. I think that would be enough for preventing merging
> > kmalloc caches?
>
> After digging into the code of slab merging (e.g. slab_unmergeable(),
> find_mergeable(), SLAB_NEVER_MERGE, SLAB_MERGE_SAME etc), I haven't
> found an existing mechanism that prevents normal kmalloc caches with
> SLAB_KMALLOC from being merged with other slab caches. Maybe I missed
> something?
>
> While SLAB_RANDOMSLAB, unlike SLAB_KMALLOC, is added into
> SLAB_NEVER_MERGE, which explicitly indicates the no-merge policy.

I mean, why not make slab_unmergable()/find_mergeable() not to merge kmallo=
c
caches when CONFIG_RANDOM_KMALLOC_CACHES is enabled, instead of a new flag?

Something like this:

diff --git a/mm/slab_common.c b/mm/slab_common.c
index 607249785c07..13ac08e3e6a0 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -140,6 +140,9 @@ int slab_unmergeable(struct kmem_cache *s)
  if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
  return 1;

+ if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC))
+ return 1;
+
  if (s->ctor)
  return 1;

@@ -176,6 +179,9 @@ struct kmem_cache *find_mergeable(unsigned int
size, unsigned int align,
  if (flags & SLAB_NEVER_MERGE)
  return NULL;

+ if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC))
+ return NULL;
+
  list_for_each_entry_reverse(s, &slab_caches, list) {
  if (slab_unmergeable(s))
  continue;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1%2B_Q%40mail.=
gmail.com.
