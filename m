Return-Path: <kasan-dev+bncBDYZRFP3QIJBBB4GZOVQMGQEMRFC2IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C301809D01
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 08:17:29 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-67a940dcd1asf23442906d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Dec 2023 23:17:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702019848; cv=pass;
        d=google.com; s=arc-20160816;
        b=L0A746Sq4lVyQjzNuV3iCujj16mBNfexKS0p3zeVfsMDWCquhcrw6r9qvwYTsw69m9
         OrSsMLsT+EzHh9Xwg5WKxgZ09PWEDAXFA4ZO0nduR1p9kQy924xSy0xO7+IIy73FHZc4
         07MUW+cGOkEnTTyAS9H9TfjPEpHONVzXv9Fq/peVcTOPQMuttUV1HdzFVjZswRcqs8j2
         g3FUfj15lBgYS3ptynefYt7sv8Zzn3GMgOSnu23Z8eXsqgJo+FRf0bfJzrxTnlYKi8Zd
         7W17VcqdwxMJj83xx3t8S5Z5kZHTsm4sa5jXIE73RNlZstJ0UFx5yDewLVuU3msc6Ln/
         sbqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=th12p3nHDw27AI/4Ebnxda1lbQcN++gdCCUVh7TEVKk=;
        fh=f1eG24fLE50oJLlpN6q45mWEES4s7GsWvScw+XEiX5Y=;
        b=ZEbFqO8mWwQHTXE1FZvm1O2yLoULLpd9iQa8+XATtUlm2SMksB5EIvez7FeWd9UwzE
         /E9yCV8209mp70f2lkz0sKPZ0Qc7U5DyiD+KJiZMzRxb4pODm9Q1zoHWNuJLyqlDkJSh
         IAeQZdbZwIlXaTHlSB9qIFgmRW9wy+kwfo+Bk2YMuueKr1vXpU9FiAIQQqJV0kyxAlkf
         Mpdzzsdy8dlZbeyhEMzOzxl6yhiUmmPQt+r5dVpdvZKnOtTdwizEY3a39SDfqDILIisB
         hC+ENVwx5y4kx7Ie4PPojdtuCXjKRKJ4vOdsF3dfTst9BEp2Lrw1jLtB0+/TcrpcWov5
         SZlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.161.53 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702019848; x=1702624648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=th12p3nHDw27AI/4Ebnxda1lbQcN++gdCCUVh7TEVKk=;
        b=Hg0hytf8Wzw2JabGh7hiIG4lMt9FPM7wULRQQ8B8+bUKL6TaNy5Y9vy1zt8bhrsqo4
         TfjnLvfWg+2kODQreInVatuRDtKvtnPsWzGuVEkSNlnwS4jzOp8cXKDX+xXeo10CBGpw
         Rq3aLcYpssQqsB3M1Y4FrCBkaYIIvC6hS7AuArLYvMDvdw9d8QIjm8MiR4bM6lxP+Tyi
         P91bVSKYmA/3FKhK0QGgddXNdjpg952R1gekDEwQjSGtvuBIATAzbssyXM5Pem56qFKF
         8Gt3PvhCZRpscwQclu5OvZ6U6gPVLritqXVA8te2DrRMZSTie1u/gdHb2vs9LT+LDsZ9
         LR7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702019848; x=1702624648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=th12p3nHDw27AI/4Ebnxda1lbQcN++gdCCUVh7TEVKk=;
        b=ZbCGbS/SKUWAxE2rUt/GCgfhXUa53yxmLICPtaLDsmxGczTDjTAx/6NzTKgFcyZo79
         V7dnFiUemrniOzBDdVvQAvG0Uuciqt7oyEvt3oUP55DlBgw5Wahe+3NcWTlmmMDs7Fz3
         zOnnqERffh9mtcSanrxWLOLxpbTJPXOBtKv3bxSJ0UJnr2W0PZzkLMVXwFSs6cwGoadz
         zJYzIcRZ8rr3suZlUyyRE7YfSU/bnQ0/z3jy0WLXdT3cfG9fotfLWTuZyY0hveMg9Xlt
         ajsR4ZisVj6pzf9+H49PYCY9dgRuUK9L8Lpg2kmSDq3NU+pxOiyAEYVNZ6ZRKxlBjdYY
         Hn4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx1sKS0MFUBq7hoIR7JvtELgUmYh2I8wLtbqWWk/VUYJcTRUd13
	V1rQ5X8fVi6bqrU2YHkoJ7g=
X-Google-Smtp-Source: AGHT+IFCr+62dcC0RgeS2M3ukgInq7YDwBRdXlkKP4Rh1kVA3l7eqcj0JyJ9qRCK+7i5pA6OrraZGw==
X-Received: by 2002:ad4:55d2:0:b0:67a:a721:8312 with SMTP id bt18-20020ad455d2000000b0067aa7218312mr3433841qvb.108.1702019847830;
        Thu, 07 Dec 2023 23:17:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bec6:0:b0:67a:218c:efcc with SMTP id f6-20020a0cbec6000000b0067a218cefccls1698421qvj.1.-pod-prod-02-us;
 Thu, 07 Dec 2023 23:17:27 -0800 (PST)
X-Received: by 2002:a1f:ec03:0:b0:4b2:c554:dfca with SMTP id k3-20020a1fec03000000b004b2c554dfcamr3108915vkh.25.1702019847047;
        Thu, 07 Dec 2023 23:17:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702019847; cv=none;
        d=google.com; s=arc-20160816;
        b=FJQvexRsOuWrd/R3SqZm7MgIFUhehClYbYhvRxD5fKdkYFUOuPtK5+X4PVAIQe8nU8
         IAkVl/WIQoBvFA1NT/ngnkn2lmwG4pFC6CGgXITPb5NyArlIniOBzKeP59MRZCrQAHrD
         82ahYvAR+Hl9HXpMLn0GMkOIcd0J/3Zc8AJ14LQJYEyADmdwlASsYy/IcpCrCmb1RhJW
         Gv3GR2ZXT9BeFl4RA1d1Slh3raa5k7upwsdzsRZvi19cKzggjH1THTPqv5S5tR60VNl8
         T47W64t2VlOPovh2RseijolgzuxSr5X1gMwVwfsN7q8ehi++/i61Dogt7mzGRSTdU0Zg
         gXtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=i7Vin8BT3wpq5T3wEcuxWKKOuHM8AGLU+CBTDMoLXsk=;
        fh=f1eG24fLE50oJLlpN6q45mWEES4s7GsWvScw+XEiX5Y=;
        b=y8fcB7l7bozAbl8v4Tu4RL9oUVa6uLXhZc4Ouh/5QXUJXO1d4QN46s0QeW29gbQ/T5
         TE+iDvAwqC3XeaHy59gVW55u0uvo63rJMIABtnXXHkAYFzjMmS5Ea623rqJXRaMNlikp
         l0LDqvBbEpKngL3bMHtByHGcj0HjaZy8IURRCUPbID2FfN6iHR2n6yCwf7XSy3dEHQwk
         RS3/6TygiBh+N7ztbJAHyuTMt6s3/sz8P/oYrBlu5FRHM1UQuyzFlzQJZjZGXDb41GZ0
         Nw738FGZPA0YYMfDmgG0SzbIWWmfYhD0otrV6ao5o7pj8ZnRgMEa8oAooikO+J2t4vHG
         JF9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.161.53 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-oo1-f53.google.com (mail-oo1-f53.google.com. [209.85.161.53])
        by gmr-mx.google.com with ESMTPS id eg3-20020a056122488300b004b32b7eae04si144601vkb.0.2023.12.07.23.17.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Dec 2023 23:17:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dennisszhou@gmail.com designates 209.85.161.53 as permitted sender) client-ip=209.85.161.53;
Received: by mail-oo1-f53.google.com with SMTP id 006d021491bc7-58ceabd7cdeso878422eaf.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Dec 2023 23:17:27 -0800 (PST)
X-Received: by 2002:a05:6358:4327:b0:170:17eb:1ed with SMTP id r39-20020a056358432700b0017017eb01edmr4228974rwc.48.1702019846351;
        Thu, 07 Dec 2023 23:17:26 -0800 (PST)
Received: from snowbird ([136.25.84.107])
        by smtp.gmail.com with ESMTPSA id y130-20020a62ce88000000b006ce9d2471c0sm956133pfg.60.2023.12.07.23.17.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Dec 2023 23:17:25 -0800 (PST)
Date: Thu, 7 Dec 2023 23:17:23 -0800
From: Dennis Zhou <dennis@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@arndb.de>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH 0/2] riscv: Enable percpu page first chunk allocator
Message-ID: <ZXLDA3zObbLybTJB@snowbird>
References: <20231110140721.114235-1-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231110140721.114235-1-alexghiti@rivosinc.com>
X-Original-Sender: dennis@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dennisszhou@gmail.com designates 209.85.161.53 as
 permitted sender) smtp.mailfrom=dennisszhou@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello,

On Fri, Nov 10, 2023 at 03:07:19PM +0100, Alexandre Ghiti wrote:
> While working with pcpu variables, I noticed that riscv did not support
> first chunk allocation in the vmalloc area which may be needed as a fallback
> in case of a sparse NUMA configuration.
> 
> patch 1 starts by introducing a new function flush_cache_vmap_early() which
> is needed since a new vmalloc mapping is established and directly accessed:
> on riscv, this would likely fail in case of a reordered access or if the
> uarch caches invalid entries in TLB.
> 
> patch 2 simply enables the page percpu first chunk allocator in riscv.
> 
> Alexandre Ghiti (2):
>   mm: Introduce flush_cache_vmap_early() and its riscv implementation
>   riscv: Enable pcpu page first chunk allocator
> 
>  arch/riscv/Kconfig                  | 2 ++
>  arch/riscv/include/asm/cacheflush.h | 3 ++-
>  arch/riscv/include/asm/tlbflush.h   | 2 ++
>  arch/riscv/mm/kasan_init.c          | 8 ++++++++
>  arch/riscv/mm/tlbflush.c            | 5 +++++
>  include/asm-generic/cacheflush.h    | 6 ++++++
>  mm/percpu.c                         | 8 +-------
>  7 files changed, 26 insertions(+), 8 deletions(-)
> 
> -- 
> 2.39.2
> 

I've applied this to percpu#for-6.8.

Thanks,
Dennis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXLDA3zObbLybTJB%40snowbird.
