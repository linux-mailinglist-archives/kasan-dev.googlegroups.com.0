Return-Path: <kasan-dev+bncBDW2JDUY5AORBVUPXGXAMGQEGO6KRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED19D856ACF
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 18:20:23 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-563a2279f1bsf1362830a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 09:20:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708017623; cv=pass;
        d=google.com; s=arc-20160816;
        b=jPtPyuaWkeDRwiitKcQWW6Cw9Ib92F8rsTTnhsVhnaluFApNuhNWXzZg5Rm3L3QoS2
         bAE4oPpkhSMzWPwN8LK7q3CKOIYWsFrJPeIs3eCbQItngVBArK1UWmR2nGAzG3RmSoWU
         3V/JAaqPsDZRkymYgEbhwXaTRtXIRDKMJX3oCLb0g7Y5atel1aW9va/4yy5/K1gPFlPO
         je2bOrsq0xjum6fcd5c9d7GnIRlkCRAXnZfBL1gZ140xyT9/hOTKwaidnZUsWLd8JbXx
         b4cD3oMGrIu+OTqJiwPIR70GnqtsSG5Yjmx1jjIEXKpSYdWCo9BHWtsnR/xqk3VHqnz4
         lnjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8RkXKB/Xa3pjUYhkLAaKZRSBC24kbyXBwKP7Na+PgDU=;
        fh=mSUjbuuOdVlmszf3vKjWup0VU6u9H/xvjgYtFyUFpIg=;
        b=zs3tDP50af1YjgbZoAcc8F+oV/tgbzyQK2qT2dkBiAmImwGDpYQpvhg+1iBFI/LLKF
         YKNcwZ0lGVURsxo/+nJqDK29XqOg7TNY5XYAmNDJwwiFPF+DUJV6Bg9oqSHo+jFiOe4v
         s55KFvvXghZv+X6WUF8bRQKt26L9QrDASUGZjje2zLyhUaaQiqxjy2NxKmNncgXUPH+M
         kHzIMbyo69d+eBmmMjXvhentFarc/lR28upsB0dLOO4Moa+N+lV4LPLU1H/prF4uOtvo
         Bqi5QpSpB9W9QuaLkE3lYtXK+BFni0h9OxK3RHBJJKrijd7a2ZwwC31/jJHbaK141uPV
         BRzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="AQUTQ8I/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708017623; x=1708622423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8RkXKB/Xa3pjUYhkLAaKZRSBC24kbyXBwKP7Na+PgDU=;
        b=MvWwi0F2OG2G3hIbHaS8wBmiV/rMy2lSbb+UO5bFTG4VPjGTUZ8Ub0HrDwN7oZRO+V
         TLkT/D6E6ZcrjR0i5jNGupqYxsRHrs/ZMJQM0fgFRhnXasMoFRnEFL8cR06+5zze6w/H
         e5pzZSKb4O6Qqab1bAjDL0Mv/dVh2QVEZD8AasfA48wCsCKL5BC0LkvDwssu058s8m6l
         wONqCijhPys8RIXHFoa0ouRTNKXA530/fj1zg3Bb5UFMhfnhXVYx1lA0i8uZnWE+4BYH
         QMe5Zb12N3rxGQr+bU2RGdY5ulbFKe5gmNK7MbVwwFaneALUZLvjZKBMzhUnwrwQ0vxV
         JV5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708017623; x=1708622423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8RkXKB/Xa3pjUYhkLAaKZRSBC24kbyXBwKP7Na+PgDU=;
        b=UFJQpzDT8kosZOJ2uv6pR55e9XyZAo+pa3sddQo7+RlMrWa+YQ6iWau1veno+72hUd
         TATmLXpGZK6t9+rdFpfOvrSYLauJDPU1ynm8Np1EDAneklsHAVsLZVGd8KOZoU1kFmN/
         1XCUwaFiF5Xs96sRXDW0TuT6wT0rIcdr35xhqwiVk+pS9GlAST7kA6xwF95y3B9/FEzJ
         OkGUZCPMMOJV0RqASqYidOaEB0c3HjEZ+BcCOMqDhivXf+b+Fsyg976fCHwDCNk651P1
         pyOadCtmFqSQi8YTo5st5z46DF630UAXqBSVolGQnwUhStEiYRSC7OVjZTUB4k1ReV7Q
         ccmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708017623; x=1708622423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8RkXKB/Xa3pjUYhkLAaKZRSBC24kbyXBwKP7Na+PgDU=;
        b=U6yPHAwH936BPjxcnHtq9cKUJj7R3fTWRoXHgQxaQfx5LHE5yzolYxITf7/mnxQEBg
         iIOEtnwRZpDqFAegQLBQFerKX8VeDlZL0TL0SYIxKTMZ2SSlzxz2fd/CGU8QdKvQvdCv
         xZTi0Y1vYwDvziSDHgl8t/z1SeltRsLZjoZItfsAr3Q+ORzS95Lwk8/o+fJdy2hOXQRV
         0rXeNfqbdgZ6bYc3NOHq604QbbB+2dSyq8vSm1GVOVCIBYPCXyj8fkCtgVe0K3yf0zdU
         xJwDl88aimgDD/p+SCsUcl5yg5OQ8IWJoOhdEetrdwU7lKFIK283H7nMxywbId26BeY2
         WAWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtHsXaDzWNAdI1hiNniI+qTdXW5p86PP9u4lMnF0a8ZYHo1sW61KcsKYgIHR2X4yjOBMsUPpybti0En0c1RMn1SMyI15xQtQ==
X-Gm-Message-State: AOJu0Yy6ZQL4QfoI/wP+4hR0+HdJ5ANK6xXXWqVLQ5vv0tsVZ3HaT6Aa
	kBJFxdd8rLe/U3Vc0l90XPMTP+YIh/N8Ss7KgfE0HjpdTkQOdDcr
X-Google-Smtp-Source: AGHT+IFGchOLmK/p8mI9dX/YDXwgPV0nZPzUi9kY6Bwv/CA26+O9C1StyUgOkfzDaD5zqMliDcNujQ==
X-Received: by 2002:a05:6402:43c4:b0:563:c951:838c with SMTP id p4-20020a05640243c400b00563c951838cmr1235133edc.18.1708017622992;
        Thu, 15 Feb 2024 09:20:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:448d:b0:561:63b4:b06a with SMTP id
 er13-20020a056402448d00b0056163b4b06als660111edb.2.-pod-prod-00-eu; Thu, 15
 Feb 2024 09:20:21 -0800 (PST)
X-Received: by 2002:a17:906:1c59:b0:a37:30aa:3cf3 with SMTP id l25-20020a1709061c5900b00a3730aa3cf3mr4477556ejg.25.1708017621268;
        Thu, 15 Feb 2024 09:20:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708017621; cv=none;
        d=google.com; s=arc-20160816;
        b=IXq8r+ebKpvqJ6XMMzLIGOksjDPYaIT0k6Obh+m/jJdtmbuvMMlxN7kgdqMnzztkTi
         axsg/PPOjeyeC2vXTQwTEp0TbFqFop5bHGAjVRstzEGwOfFxzZ7YiG8a476yBpayyfI4
         swQv+wq5wVBFSBEVQMzi/cOw75tL5MPWe0bOunjEWHidMigL0WeKXNUmVN345xfPCJnJ
         BKumRJMNCr0q/CgTSPFIcIZ5xYBzMgD8Oo7e64uvDdFICA8pyYylqG0SItq9on/RsEa4
         m0K0RDIPkjFWIQE6XN/7pXxVDIYuB5LWF5TR0WSUCbkFPwNygtoKsS9nN+xwHMzhmDf0
         eYgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wsy/rTXATJpQPiJZK0atMbxDxFPdAPeYrtGGTVAUIDQ=;
        fh=KNQQtRPUSE0ZCvkFQkawHZoC0tgd0KS8JBs4Z5NZ73Y=;
        b=FUeZFJM2wjBqnBh9qkbSLy9lBYbMUJ/P+7bn2Z6XepWBsaCJZmR4mAB6Pi+iFdDCo+
         qVquJ0JESZ0l/zsu0MO1aHOo/ZIxqV3uI3tq2dH1WZ/SFJW8U2txiDBwCifwF08ZNgId
         GhlqWfBeDqvWvMV+ESuIaHUN4bW7J7ZScjhFg80LolUEieWcr2GAWFTo46TvP/L0y7j1
         n6UW/AbxotY6fLVd1ybFvEHqgva81KGd7SiT2ZDCywtq45k1l4QIECdw7KMGIt0P0FuS
         uwoj47VdBSs+x939ERnvziI65Yj5m2oWEGBsKZQVs4qL9PP69WlCxf1kGEBeQstMtxzX
         3EUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="AQUTQ8I/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ji12-20020a170907980c00b00a3cffbbb483si80285ejc.2.2024.02.15.09.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 09:20:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3394b892691so803648f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 09:20:21 -0800 (PST)
X-Received: by 2002:adf:fd42:0:b0:33c:e075:b075 with SMTP id
 h2-20020adffd42000000b0033ce075b075mr1938968wrs.33.1708017620752; Thu, 15 Feb
 2024 09:20:20 -0800 (PST)
MIME-Version: 1.0
References: <20240213033958.139383-1-bgray@linux.ibm.com> <CA+fCnZe2Ma6Xj5kp6NK9MekF+REbazTFwukdxkgnE9QAwyY=NA@mail.gmail.com>
 <37d83ab1b6c60b8d2a095aeeff3fe8fe68d3e9ce.camel@linux.ibm.com>
In-Reply-To: <37d83ab1b6c60b8d2a095aeeff3fe8fe68d3e9ce.camel@linux.ibm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 15 Feb 2024 18:20:09 +0100
Message-ID: <CA+fCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0EA8RAtyr-KgkHdg@mail.gmail.com>
Subject: Re: [PATCH] kasan: guard release_free_meta() shadow access with kasan_arch_is_ready()
To: Benjamin Gray <bgray@linux.ibm.com>
Cc: kasan-dev@googlegroups.com, mpe@ellerman.id.au, ryabinin.a.a@gmail.com, 
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="AQUTQ8I/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Thu, Feb 15, 2024 at 12:25=E2=80=AFAM Benjamin Gray <bgray@linux.ibm.com=
> wrote:
>
> > We can also add something like CONFIG_ARCH_HAS_KASAN_FLAG_ENABLE and
> > only use a static branch only on those architectures where it's
> > required.

Perhaps CONFIG_ARCH_USES_KASAN_ENABLED would be a better name.

> That works too, PowerPC should only need a static branch when
> CONFIG_KASAN is enabled.
>
> Loongarch is also a kasan_arch_is_ready() user though, so I'm not sure
> if they'd still need it for something?

And UM as well.

We can start with a change that makes kasan_flag_enabled and
kasan_enabled() work for the Generic mode, define a
kasan_init_generic() function that switches kasan_flag_enabled (and
prints the "KernelAddressSanitizer initialized" message?), and then
call kasan_init_generic() from kasan_init() in the arch code (perhaps
even for all arches to unify the "initialized" message?).

And then we can ask Loongarch and UM people to test the change.

Both Loongarch and UM define kasan_arch_is_ready() as the value of
their global enable flags, which they switch in kasan_init(). So I
would think using kasan_enabled() should just work (minding the
metadata-related parts).

> > What was this data access? Is this something we need to fix in the
> > mainline?
>
> I don't believe so (though I spent a while debugging it before I
> realised I had introduced it by changing kasan_enabled() dynamically).
>
> In kasan_cache_create() we unconditionally allocate a metadata buffer,
> but the kasan_init_slab_obj() call to initialise it is guarded by
> kasan_enabled(). But later parts of the code only check the presence of
> the buffer before using it, so bad things happen if kasan_enabled()
> later turns on (I was getting some error about invalid lock state).

Ah, makes sense. Yeah, these metadata init functions should work even
before kasan_flag_enabled is switched on then.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0EA8RAtyr-KgkHdg%40mail.gmai=
l.com.
