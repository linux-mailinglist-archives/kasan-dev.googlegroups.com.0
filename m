Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBRNXYOVQMGQEDD7AC4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E031B80798C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 21:38:30 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-58d0c968357sf203260eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 12:38:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701895109; cv=pass;
        d=google.com; s=arc-20160816;
        b=iulHba591gg/LqtOFjFRqAeTPy3pK0VZSEoJ7uIkUXuGZrA4WmhFXURgJZesU+eCjS
         zbfUw7nD0BojnGMiuVTWfb5V6zT0s7CppeInXY+Ox/RY9DuTQNtSeIXe8bULAEnD0XIH
         +aSM5ST1W8pi4X1pOXBhCulyAxs5/izpo8UDkSTyBafwQdAncqYCq9QqHDDXJW6RWuXx
         hRXKR1Z+hQjHJWp40beeVr+3LZk0Fz8Qhd3s1MVYgeserb1KArXwI5GVlAePb/sJNvvW
         5AxEyUTb8yB/W022LIk6MOXZeiE2VwfqdgQvqbw9Xyb7eZJf+Wei1/i7Azc0KZImPiXs
         BeSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4V/PlIaYZnchLFcZSXBm56R54pQfp8HmC3mZyK1XVNU=;
        fh=AXgH4/fcqcgqccD/cDS/xy+NOvgQKgKUMuPovHDZvQI=;
        b=fjOUQA/XT/SzXJGs7YMDnnFY3g2q1w18nr6yZ46V2RU3OloFkqb8clny+Q2UJu2vqd
         Wcpif/SfbnUq4mjJ11A2eT484VG70DLbAStupinuz8h4c/zzmBvJao7n1dIDFyl6tf5r
         tAw0sAiLhNeOVv5RlkE6x5YStQ3zL7awrTQcdbjXz0rR+Mr817lovd+qRFV2MW5EfC+j
         roX/Xru3J8xB6Rpw6WSWHJ4YGFwcnCCshA4kAan5rdmkhwfrgcMpIgOSf+/sRvI4lhSy
         dbb/6t7++OJowb3xa82p0e9JhfGjLFA58lrDHorjNNgW39z3Pe32FRfAB4e3rtXGpneu
         A8hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iqr9VLob;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701895109; x=1702499909; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4V/PlIaYZnchLFcZSXBm56R54pQfp8HmC3mZyK1XVNU=;
        b=eiC8X0YGoimXYd70rc6zgoO5xhpXPWyXwDFEZDw4DZHNI1tB4fvAjxPqQF/JEYf6OB
         WgbIvku8y8GBpO7Qr+n3BUu9q/WaWqvf/8GAsECMSGnJ+Q+r9euWvFth1vaTEtS8ZdSI
         8M4KF21D+bHq7xosCDOfUR0lYCMDDHH/MgoQxS4Uxjg7T7WhH2M0G0eqGP/FP0YaSN+r
         1jwRnYc2ba0OsUR9FozYL13jImlnDI76SiU4R5XkrlLAQaHdBh1ozCpgSdctj6T0j21Q
         +1EyFnTfYKOa0QPze5fXkTon7M3QO0WQZtvrp2XTQbRp1Bxy9FlR+FvnGLKCaHhgTGz+
         5bPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701895109; x=1702499909;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4V/PlIaYZnchLFcZSXBm56R54pQfp8HmC3mZyK1XVNU=;
        b=Gbe1pN01le3UEX/rmxpLH+5F9cUnnsUr609DCJuWQRSMVMmitWbzJKcfu6AuWwlzOW
         fyh4d33PFYoWJOfaFNLnrrLPTNHQlLNs0DABQdCB9fGwbsmP6lSSkxiioHd0Dtp2rgEd
         5Seqe5w6smNTnhpY2oxdte7j3XO9MX8czGC20pIbKB1dr5tPNDqofciTwCFcJzlVgvy+
         WxA5X+45hSHFL3k7IfSzBsdZfPe8KgkNJuN6urkJEUEsrXXha06tjJNqF3o+Ol1IJ6hc
         mizDlOkatuAQTJog0WuPmLpbRQjmmbgDJLY+clK77akiG+sfhY4+AJmMk7ahKwBIrJH4
         SKaA==
X-Gm-Message-State: AOJu0Yzb627Y5wLnJjXipVAIx3Cl0Xy8ywPprFRLIAXhhkFDaO1m3iox
	q94NVcN7Z7LLi19vFsA/4PM=
X-Google-Smtp-Source: AGHT+IEohxTP/kI4m0ZQLgVu/5A20ko0KYzsPfdHv8n1rNevv/q8KoxPDGEiGcadodJkWY5JQG4Whw==
X-Received: by 2002:a05:6820:812:b0:590:19c5:5b26 with SMTP id bg18-20020a056820081200b0059019c55b26mr1644341oob.4.1701895109400;
        Wed, 06 Dec 2023 12:38:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2224:b0:58e:2769:6234 with SMTP id
 cj36-20020a056820222400b0058e27696234ls476931oob.0.-pod-prod-09-us; Wed, 06
 Dec 2023 12:38:29 -0800 (PST)
X-Received: by 2002:a05:6808:3014:b0:3b8:9534:8ce2 with SMTP id ay20-20020a056808301400b003b895348ce2mr1493377oib.3.1701895109040;
        Wed, 06 Dec 2023 12:38:29 -0800 (PST)
Received: by 2002:a05:620a:458b:b0:77b:cc25:607f with SMTP id af79cd13be357-77f23c645bcms85a;
        Wed, 6 Dec 2023 11:00:31 -0800 (PST)
X-Received: by 2002:a05:622a:4d0:b0:425:4043:50f0 with SMTP id q16-20020a05622a04d000b00425404350f0mr1837058qtx.127.1701889230299;
        Wed, 06 Dec 2023 11:00:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701889230; cv=none;
        d=google.com; s=arc-20160816;
        b=yvc9VYuTh59k5w2i6ZHTBhj/hXKVCdu74RPCp0VF7sKToZ0AsYYfDHTA/y+hf7JjK5
         LmmtVSUTgfCvMquoLSpJEip//JlK6w9JMnl2kCknjnRkHn4Bts+v0upSnBfWvTU00Jhn
         4kaAtCXClaFKsgrWbGzGG/WNxUQgtbyaNChiDaBF0A9Oijv6FZ8ZtLqX/9EC61p14d9O
         7YXHb/V6tt09BaPoNN+6rVVTTVet3bX0vvN3zCT2wJ4b0lY7VNGw4jIrQHjRUBL4CCtg
         77Of4PviKQ8ST7ZtNjg7DLbMqkP8atN5THUPbsZSmSO8TvcDuulBKryXt1x8VJ9mukE+
         jFbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=gzbohbzVePtQAWojGFBvS0mVM42OxJTLPxt60AU1LYc=;
        fh=AXgH4/fcqcgqccD/cDS/xy+NOvgQKgKUMuPovHDZvQI=;
        b=fOqNP8yrMi2tMHuY9qKDd/x1gXr98gyVDFCjbq11jIcUJWr3rc6IhQsIEfb0HU0dNF
         BI1NunQM0RQcfXlTT38LxdIOkiodHr2nXwTRKuweREKAO3G7ZafxCct+V+YzOXOejtVy
         46HVkkbMYHTfdFRvHeZGeSM7hRPSooZeXlGZrBPh592vIj4RkyliZLRm4g76p9q5NtnU
         p6bZDzNyRxH0ITut/t77uMwwBz9QBS1Pj0btM4ZADJqykHjGHHmBkLqYDdJR/UR+FOog
         I1qIBJ79dnhVrj/WvAvwo17VWFSrS6kgFuEbxqf+mvDbjBxopL63/Tl2fu6eFFtNE4fW
         uC8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iqr9VLob;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id fg20-20020a05622a581400b004239ed495d6si134399qtb.2.2023.12.06.11.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 11:00:30 -0800 (PST)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-5c66bbb3d77so58349a12.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 11:00:30 -0800 (PST)
X-Received: by 2002:a17:90b:38c5:b0:286:aded:d5de with SMTP id nn5-20020a17090b38c500b00286adedd5demr1064920pjb.15.1701889229200;
        Wed, 06 Dec 2023 11:00:29 -0800 (PST)
Received: from localhost ([2620:10d:c090:400::4:27ef])
        by smtp.gmail.com with ESMTPSA id w4-20020a1709027b8400b001d049cc4c9asm169921pll.7.2023.12.06.11.00.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 11:00:28 -0800 (PST)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 6 Dec 2023 09:00:27 -1000
From: Tejun Heo <tj@kernel.org>
To: Alexandre Ghiti <alex@ghiti.fr>
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>, Dennis Zhou <dennis@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH 0/2] riscv: Enable percpu page first chunk allocator
Message-ID: <ZXDEyzVcBOPUCCpg@slm.duckdns.org>
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
 <f259088f-a590-454e-b322-397e63071155@ghiti.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f259088f-a590-454e-b322-397e63071155@ghiti.fr>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iqr9VLob;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::529 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Dec 06, 2023 at 11:08:20AM +0100, Alexandre Ghiti wrote:
> Hi Tejun,
> 
> On 10/11/2023 15:07, Alexandre Ghiti wrote:
> > While working with pcpu variables, I noticed that riscv did not support
> > first chunk allocation in the vmalloc area which may be needed as a fallback
> > in case of a sparse NUMA configuration.
> > 
> > patch 1 starts by introducing a new function flush_cache_vmap_early() which
> > is needed since a new vmalloc mapping is established and directly accessed:
> > on riscv, this would likely fail in case of a reordered access or if the
> > uarch caches invalid entries in TLB.
> > 
> > patch 2 simply enables the page percpu first chunk allocator in riscv.
> > 
> > Alexandre Ghiti (2):
> >    mm: Introduce flush_cache_vmap_early() and its riscv implementation
> >    riscv: Enable pcpu page first chunk allocator
> > 
> >   arch/riscv/Kconfig                  | 2 ++
> >   arch/riscv/include/asm/cacheflush.h | 3 ++-
> >   arch/riscv/include/asm/tlbflush.h   | 2 ++
> >   arch/riscv/mm/kasan_init.c          | 8 ++++++++
> >   arch/riscv/mm/tlbflush.c            | 5 +++++
> >   include/asm-generic/cacheflush.h    | 6 ++++++
> >   mm/percpu.c                         | 8 +-------
> >   7 files changed, 26 insertions(+), 8 deletions(-)
> > 
> 
> Any feedback regarding this?

On cursory look, it looked fine to me but Dennis is maintaining the percpu
tree now. Dennis?

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXDEyzVcBOPUCCpg%40slm.duckdns.org.
