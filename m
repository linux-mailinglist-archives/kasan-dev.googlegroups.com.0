Return-Path: <kasan-dev+bncBDS2TFHZQINBBCHUVHEAMGQEFVGSSTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 03B05C33220
	for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 23:11:22 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-340ec9b90fasf1134655a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 14:11:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762294281; cv=pass;
        d=google.com; s=arc-20240605;
        b=emqfaCwUmh35DS0QZPNY3jmm3wbGgPMihX0bAtu1tIMbYWVZr6WNvVvHlEvS6VH7/S
         7AOqT7j+0JHtdHT0MsS83L5tU37PU09qhAdlFUOoSUGzc2egUydIIn/BXRzb2o/SAq8c
         0fly3YzhHXCMp1CYr8YMerZSgbzrJhFr3XNPkjGS+vnMfi50+yHNcP7yqPCERhUx/X9R
         fVz4aVOvTRjYONQkRSQ1gyOO9d1jZpzwcJ1GSBmgJ9LlIlgADI3C1ThTwaiL8PCyBw3f
         FiXTpFDlmsc6CdyLH/KBo4PDl71f1ZYYHn/mqISBXptgBFjvSso1BmxY3FSBSlBWwmsL
         g+Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=SMxc507mqDnW0H7XMeoKMPsZIghDWGbSu4w1Lj5WXo0=;
        fh=Xa8wattEKZNCDkBX9R+OnbqZ4uiEXygQA1gr28uO6qo=;
        b=ZuU8hvG0sS9GObtdvhrnaaCtPCIie8/aCmfbDfEJIdsRdkMfqZCKNfIR4IrjtiMJkl
         c+Iok8FSnXCkSWKqdn+f4LuAPwjuvMTOgwT32Us745TQR7LZGpFsJIu2J2b1QWyGQAwk
         LgXecR3mbHK/Bsg/YQnq8m0cIaQKkIpb7kTeuTwOiC85/3G6I67c1StdKZj1T7oMVKFC
         RyES9BORU4V1MysXru7LZ3AqPTAhxG15EXF+3EsX/H2VPM3KeST816UygELY+rizB2Cl
         4kUTN9tJgpUx2DqQP7p+0TjODznUa9VKRuqdg8hCH38KBGo7xU8hZsg7pkbPoYNv27/I
         oNRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=HL8+OWMk;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762294281; x=1762899081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SMxc507mqDnW0H7XMeoKMPsZIghDWGbSu4w1Lj5WXo0=;
        b=V6VNjRRSnJurOTqx0RNCAXEG1qMgYxOR6lk4znJdXiMLbdyEl/qOoF3SOxhnb06bpl
         bpgUc4dPOUUFI8Ds/E0zI/nlCBxQ/8K6EukhqBvEbYhcB2Z1IAG4RdMonj9QjfpyVfI2
         +hctuZcUt5/YrHUmUL/i3TBfyFnfyQdhnKsr31cPDP7iiqeInNgIBlFnguSXjEm0Duw0
         J1OrBowNmZrlbY3yKC2yzC2EBMCIRrQNeXO8OJhly1RdrnAc9VN7q1wjwQnQPq3cAPjm
         u6E5ZiSQNgxH7+Rv4BpB4ppqCG2UOOhoqHHYx0MxaG7YAnoqlknTpxkWldOGtiNO1eQm
         4iEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762294281; x=1762899081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SMxc507mqDnW0H7XMeoKMPsZIghDWGbSu4w1Lj5WXo0=;
        b=uu/hn4whN75fNz+lIg7IGRHI0FE0NZX+NmAkpdKcrr+6ovzvK5PT0Fgbl1/0gNqnPv
         I1XS23C1KJ7Fr4k9Hw+fymByLEpW49ouNZjlEC9Le4U2D8+nvjM9WDX6IU4tJowkpsak
         d2ZHpW8x+gCLYLYK9TBj9kT2J239wWNjyYZ+iS++A7vtmlngwiaNvoar9oRru07F6lWb
         fX12hix5ht0VZwSD6tHIuRnOD7GlsSAOHo7Dggb7CUrTygS3Ety9rZlf3Usl0qvtgLFj
         6QaGNcR9TAa3Ip+ENnTEOXBk4pLf85sbAGKYZsXy1wn4IMuCvGlLxoRLktVLl4DP+c3g
         Oo4g==
X-Forwarded-Encrypted: i=2; AJvYcCWRaIqZ+w9Hcqjzn1NmFwcPuUzZzE92urSPqCfz66Gd5cRBMgTzshi6KtcRLMYSDd9KZW+iVA==@lfdr.de
X-Gm-Message-State: AOJu0YwuS3K7UioHd6Lsmp37XiHAvmMfb9u0+eddtv38a+Ii+3tQRE4C
	MF8Dl8tbFO9HiPaxnkQCwOWu97hvDCU8vVt3/CJOLkBbM8ZkuVVOSZSE
X-Google-Smtp-Source: AGHT+IH5AN5dRGv3inHLLm78yMXtTaHdTJPBFsPlQEXs+v2vMLQYeOlx2GukwwHZRT6f74XH/+zqOA==
X-Received: by 2002:a17:90b:4b86:b0:338:3156:fc3f with SMTP id 98e67ed59e1d1-341a6dca002mr449572a91.4.1762294280927;
        Tue, 04 Nov 2025 14:11:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aQqIagViUHOWL2TpiJ0f5rNYlJNO3294Ub4tRRzQ18Kw=="
Received: by 2002:a17:90a:1190:b0:327:e760:af15 with SMTP id
 98e67ed59e1d1-3404dbef481ls4196441a91.0.-pod-prod-04-us; Tue, 04 Nov 2025
 14:11:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU8frYph8zhvNC3WWDXH7GbkXgdzLeZzAh8ZAqS9jtC47R5JYSI1XZaKGssGOdLra2ebhUkh5ODuXk=@googlegroups.com
X-Received: by 2002:a17:90b:1dc1:b0:341:2141:df76 with SMTP id 98e67ed59e1d1-341a6c4ad24mr997719a91.13.1762294279498;
        Tue, 04 Nov 2025 14:11:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762294279; cv=none;
        d=google.com; s=arc-20240605;
        b=a/b6sbtRY9YgxtYx1ALoOfgXwpHu/f1MFn9lmhfZ0rNqIOweZW9lNvux8A7/zpW0mX
         uAr/eKsx0ieOLzC6mgz2D+SgAlaqEVtLiARhDxFJOoV5QeXBPGRpHV16boNWzrceweE4
         V4aF0RM8z1oEZf93+p6TelGPJvGmXieT/Ark51bYBi/iD+kTu5ustl3C1zzS4KRxaiFM
         Q4KAHYKbsbxkEoJuuc5gXG31JSJsTXuEsZAgTAIKpL464iCgUVMWV88ZDw0YJ9qfz3i1
         77D9JVYPC34Uly77JmNSe8D6PGM4SIpdbExLYwxN2sc59lVrakMZD8r1tIlzJvPKbgGV
         A0vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=/BlojT3ZNpb08cgBE5OnkdRei3sKYEo3Zbg5wHQuBX4=;
        fh=kvLBa0t27nRVPPj1WaEReA/XynBwYVc0DBoNXH5u/YI=;
        b=NZsQFUBL/g+FdCr7yjN1K3FqkrQkOm5ZMA0g41Sv1K7ClLjdg954q7EgTFeXt7PPTa
         rKtzS+hqq8/C48ug0ULTcgZKFfb8SZxdW475ybD1P8MhJxNTgbMs65u+AQ79nEoNo2d2
         xrDeZV4BEH3O9d+3qas0STTkHfa2oBXvSMGy0sgdRGoQ/2QA0FXgXStFqiuA16DZsHTH
         T9MQ0KiA/uvDRIHyHbO8cBZxyDP9b8q0QmiCox4+/nWrQOlclUkJ6fRSngITuaCOG57p
         7ryP0XihfAZGZztOtu70xLYAU4iE/KAHvxRzUuoVyHUsB+ZpTPQm7A8NKj4b07gcyYzZ
         +ggQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gentwo.org header.s=default header.b=HL8+OWMk;
       spf=pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) smtp.mailfrom=cl@gentwo.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=gentwo.org
Received: from gentwo.org (gentwo.org. [62.72.0.81])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3417a36e6fcsi23729a91.0.2025.11.04.14.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Nov 2025 14:11:19 -0800 (PST)
Received-SPF: pass (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted sender) client-ip=62.72.0.81;
Received: by gentwo.org (Postfix, from userid 1003)
	id 822DC4015D; Tue, 04 Nov 2025 14:11:18 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
	by gentwo.org (Postfix) with ESMTP id 7E34A4014B;
	Tue, 04 Nov 2025 14:11:18 -0800 (PST)
Date: Tue, 4 Nov 2025 14:11:18 -0800 (PST)
From: "'Christoph Lameter (Ampere)' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
cc: Andrew Morton <akpm@linux-foundation.org>, 
    David Rientjes <rientjes@google.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
    "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
    Suren Baghdasaryan <surenb@google.com>, 
    Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
    Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
    bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
    Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH RFC 00/19] slab: replace cpu (partial) slabs with
 sheaves
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
Message-ID: <f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cl@gentwo.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gentwo.org header.s=default header.b=HL8+OWMk;       spf=pass
 (google.com: domain of cl@gentwo.org designates 62.72.0.81 as permitted
 sender) smtp.mailfrom=cl@gentwo.org;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=gentwo.org
X-Original-From: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Reply-To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
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

On Thu, 23 Oct 2025, Vlastimil Babka wrote:

> Besides (hopefully) improved performance, this removes the rather
> complicated code related to the lockless fastpaths (using
> this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
> kmalloc_nolock().

Going back to a strict LIFO scheme for alloc/free removes the following
performance features:

1. Objects are served randomly from a variety of slab pages instead of
serving all available objects from a single slab page and then from the
next. This means that the objects require a larger set of TLB entries to
cover. TLB pressure will increase.

2. The number of partial slabs will increase since the free objects in a
partial page are not used up before moving onto the next. Instead free
objects from random slab pages are used.

Spatial object locality is reduced. Temporal object hotness increases.

> The lockless slab freelist+counters update operation using
> try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
> without repeating the "alien" array flushing of SLUB, and to allow
> flushing objects from sheaves to slabs mostly without the node
> list_lock.

Hmm... So potential cache hot objects are lost that way and reused on
another node next. The role of the alien caches in SLAB was to cover that
case and we saw performance regressions without these caches.

The method of freeing still reduces the amount of remote partial slabs
that have to be managed and increases the locality of the objects.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f7c33974-e520-387e-9e2f-1e523bfe1545%40gentwo.org.
