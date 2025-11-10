Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHWGZDEAMGQEDDMEDMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF0B1C48624
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 18:38:39 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-656f101410bsf5123188eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 09:38:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762796318; cv=pass;
        d=google.com; s=arc-20240605;
        b=EaEeAxSydqsV+riHpTCWp1IU6vqZsnV8mgwwaqLgTUB9YviMXGyAODQPS8wjP7WVdl
         rGGhIB4crFkE915emkFyLTBtVTu0FiuIBtZeCXpVgGwTd/UKgfnjkP8UzqDJlw0zcQex
         C3dBSaqf4y/bjS6H9u68jvHCdEVEWuC33cmQ7U3ocKRDPrvRrwhY0YKB+y/7P9nq69n6
         rn45Ecat37FLOeQ94+evTqhljnAnFuam0ybm8hf+2Yv3p8X5DizbZ+ttgltSp1cg6wz5
         5eSDcByPoIoqGeaXrpdyOuN/t+yhiegmDyDRMgAGVERdoMtwisJN0ucZ0UiWUcU9LkTj
         fV6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WFfTeVRdooVYGHSIS91UYYwOtMVflR76DcrFl5LuVUU=;
        fh=qdxBLA1tiJktYWvJkZCHWe2YQBANenrVtay12T5F1LA=;
        b=FApm1k8MwkDvX3BJBY/Ik60omuYlFlywCO7OrwTGN6Qxc8gMww9shM7bI6gatkXbKA
         RHiXFpQP+FbW0NuKd/WvSF/7w3ruKOoBXQ3XfwigtuUjKjlvzLjvyMNUIImd1ns3h3RK
         OnbejpI77pwIvnXHPQjSjFpXgtjlNwvKB5YkU9n1gaH74KXDcgdShulYoLIYnvQ6rmAj
         jJXZoEe07EM9bNBOY3cXZ20xXQd26/yjnIwEtnW80dlD/akTutjjJJxP7nykbyUPHOdw
         nx9X/EKcyrt71x1ku4bc4MJO2TmpAycsUJ28AdTapM28uNmHCLYnfWITqc3/VRF5DFyD
         1IPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RuN6cRlU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762796318; x=1763401118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WFfTeVRdooVYGHSIS91UYYwOtMVflR76DcrFl5LuVUU=;
        b=n4iowD/A6puHtzj+6jfBIPZxSkIJhETwWN/lsO5RM1bXWvEIQSFsz1+WdVULDRoefv
         8OVVvV6syd18WwTicV2a3IWEJr76WxxV2N+TXuHNDbb6meZcyoqw1/PHKcEKRAIAi6ID
         RvmIUUge9ExjrJ1rHOEJsJh23oza/XKV2s1NVRWbdaSc2Oge4yMYFsV/gXfwfZv72q8f
         QYFsjtNzqSt819JqMe9Fjqw7SbmRLEjtz6PTVcLR4MOV2juMWIAT4s+zRjUdcLNcBG+k
         HBFLqiJC3MADWpBzT2rNaZlmIahFAi6KS+Wo9pVDgtA8Nbi1FwWYrHTyNCsO8RtbPUqm
         yiFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762796318; x=1763401118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WFfTeVRdooVYGHSIS91UYYwOtMVflR76DcrFl5LuVUU=;
        b=lzufUFEcU8xuVolvlb/+hvCeHydHNy+1CPFJT6+cYGTJwzUSrAz5K0i1EOCB8zZyp0
         F+QPxDE0k2NVVDEXEBlJPvvUi67+83gjLxJfc8KJodNIR35eZjzzxYMmzRpvmZIXweOZ
         yGDbwVqBjFxIy+0b9H41fhqfn5Ho7i8gH6ItOjiRqsrPZHlgJf3FLoKZ0jtXakF6vEL4
         /xWAltESiynfwhQhmYQ+GVzQaXHNsNPmC+WoqjexYKjHHRwwNhXokQcN2lFDvqp/LGGx
         DnGO1Cc7guudC0PmgD9G1e/FMj7fV5fQKEEMdB6LTGkE/fu6gqpbtUZLexNBFo+iZCy6
         zfgQ==
X-Forwarded-Encrypted: i=2; AJvYcCX1OW1kNDDDRTpEj8rzZi0gBqbm//Bd4ZF9g1KePXHQ7+oC8lFiGK3O0ow0lq/qYKPgLC2QAw==@lfdr.de
X-Gm-Message-State: AOJu0YyyPCObx6BHXk/AEDSPOcCq6nyf4FOdGUSUImmuWPx9EihitaEW
	Iw5i6ykvYi/8FJABikirVgq3knii8qoXWqmuQAvM1oqxseWAY2tQSbrC
X-Google-Smtp-Source: AGHT+IHeJB++0EJjSu5Tr9k2gv6M3beKd5hKgcWDW27omWKc7y+7nVoZOlE9PxucysJS/cR5OPRWfw==
X-Received: by 2002:a05:6871:1c1:b0:3d5:a49a:2c13 with SMTP id 586e51a60fabf-3e7c284ef75mr5669237fac.38.1762796318433;
        Mon, 10 Nov 2025 09:38:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bi0zDfTxHm66dcHpkUKR+zf9998pmeszYKNZV3dehG/Q=="
Received: by 2002:a05:6871:d684:20b0:3de:496f:d55d with SMTP id
 586e51a60fabf-3e2f527d079ls1233273fac.2.-pod-prod-09-us; Mon, 10 Nov 2025
 09:38:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2SRJgR3SXJtO/+T+ETXdxUcYAkqa3cY9gLO/iEpOz+5S/8buMj+D4qKSrCpZe1oSHPn8GsM2qjtI=@googlegroups.com
X-Received: by 2002:a05:6808:10c1:b0:43f:7a07:44dc with SMTP id 5614622812f47-4502a35d666mr4718226b6e.42.1762796317486;
        Mon, 10 Nov 2025 09:38:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762796317; cv=none;
        d=google.com; s=arc-20240605;
        b=Qf8fba8kgUIwMiVKCFxGBufyu6rWH016uTvoqraUmhyaW8VcPPpYvvArfV90l4HvTb
         hpFvLzpFfcpI5LdIfJcVFJYGHLCO6KhztWKxLU+ufnJCj2OhmnpAGeatlIAtMIrgZMwk
         27p8WfXk8V6zq2KYQHgspE5UnCcJP7hPO1L/TwIaUFPPWgrKvJe4M6ufP1wyO/Ekzm6D
         0pRgzLp4CiiLZfFd2MURkUelLgClCq26SCoP0OYQzue3nw7t1Wr7oNTYTX1nHIkaP0XJ
         d0yDP95gCymZHcMtmfWL6lMElAlGhHVBQRpXla7t957472UhhoNwIApaHD4SbOWOzp1j
         qLdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YSOpGWJwXMs0s/g4qCwlIsfD5sl3RCmHWkcwp+GKrsA=;
        fh=Tc/SF5BZW8LwogV1NlBcnb5oBZgqCNHjRO10YBBCKNw=;
        b=ZjpmFMtWYwYGKDGp/357tpUXK/Tst06qMbhMrI8UcsjSbkqy93bl1yxacohThWLVOP
         LiGWxdA0wscF10uNfgEl9gHQRiU1RHpNmIofFsNmoEuIEmeAhgR6fCUiwPV/Vb+SrqoZ
         ph8kSdr3QccnnATVTjhZv4Q1KzUPjXNgHRNDkTku7rkb04qCA22TlIlmduA4s8xnC92Z
         cfxmcMnYkPlKhLoAymH4F/iItoHuEuRfSBtBv4N3wP6o3BC2ChRy+SawBHZyi0e5F6P5
         YZ+qOXiRDoixSFdmqFfK/MjDm6rVLWd5XCORGdJux0RwX0h17C+eybsudaIt8Muxc2IS
         4u2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RuN6cRlU;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45002802dc1si223506b6e.2.2025.11.10.09.38.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 09:38:37 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-4eda6c385c0so20086721cf.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 09:38:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPV5ITnx0gYetdcVRBDHpiwa7iW3Pain2Rk3gE5T/6fEDACP7Wd5mZec8WdnD6sq/3/hxCxmOgazo=@googlegroups.com
X-Gm-Gg: ASbGncvl0+Tqacezqe3FXkKXDd307QCV8NnqglNusgVTikyzn5X0iTyTAFM5HcDYLRH
	4MlMe4ACmSVnGDb7b3AcnOmuTfZ8GV1Cm9DD3f21A5mc8YcM8C5L9x5fiaeYKpOS401ubB4FoF0
	8lYtBjM80MMEEXOl93BFn/3apQldbHnVOj4hf3kAabTLhUx6PtfuVE0ZJHYoYHB+5bb2yqP1ZrH
	kQGN8ED+Lke2z3YBC6w27ljBvQNwowFS/qeTJVOrTheS9lGWseDZB1rLZc1DFepRIWc/uupeT8q
	YA2J/ZAi5BnWOgi3lyEuSa+B7g==
X-Received: by 2002:ac8:5856:0:b0:4e8:baad:9875 with SMTP id
 d75a77b69052e-4eda4e70d87mr109099991cf.4.1762796316364; Mon, 10 Nov 2025
 09:38:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <8319582016f3e433bf7cd1c88ce7858c4a3c60fa.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <8319582016f3e433bf7cd1c88ce7858c4a3c60fa.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 18:37:59 +0100
X-Gm-Features: AWmQ_bnlgBiH0JekOxzwX-3tPMF5D_wHyW4PzCjMfs9TphH4P9izG_-i06SXddA
Message-ID: <CAG_fn=VUx7GkcjuYO3oRH7ptgKVtzQNChW1xKL+1SPfJ=XvWwQ@mail.gmail.com>
Subject: Re: [PATCH v6 04/18] kasan: sw_tags: Support tag widths less than 8 bits
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RuN6cRlU;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> +++ b/include/linux/kasan-tags.h
> @@ -2,13 +2,16 @@
>  #ifndef _LINUX_KASAN_TAGS_H
>  #define _LINUX_KASAN_TAGS_H
>
> +#include <asm/kasan.h>

In Patch 07, this is changed to `#include <asm/kasan-tags.h>` what is
the point of doing that?
Wouldn't it be better to move the addition of kasan-tags.h for
different arches to this patch from Patch 07?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVUx7GkcjuYO3oRH7ptgKVtzQNChW1xKL%2B1SPfJ%3DXvWwQ%40mail.gmail.com.
