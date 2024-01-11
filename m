Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC7T72WAMGQEOGXGD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BA1E82AB38
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 10:49:00 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dbeaf21e069sf6342605276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 01:49:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704966539; cv=pass;
        d=google.com; s=arc-20160816;
        b=KPFP6tjkL3HGuqxb0jB97d2fMU7QKbuWxwUahkBdCwbEUPKYvR6H3wGFG1cwSvuXB4
         aJE0OW9OvUke4QqGNqkGq77RpbnulIou/KlrRvtxBkJVLycgfyoi95OHLQUvYn8DrmKE
         5h7HRdCnj6GJAuml5N01CqitezDyrE4UgbkJT5v1BllDV+lvPjSLhLOdLPTl3Us3NToC
         xh01gMyJ2/uG5tpEB6DCgT7JkEE9F6eVSLImuo7k7ZHCFRvjRhAVhQVC7niWtgIocKfL
         LbYjQ6sNgdNNBWCZfBnS5uh2Hs6pJXeJ64krNIafgy4XZxDk0VAAYhE+15pUmmtBOO6G
         Hqpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xf6Mv5jbMiyEu9sIIXoYI0sxe/3rufhTw/mYj8um7C8=;
        fh=y9FUbJak5C6gzSTedbgzGWVmwnHgqmhZsHaMuLfouUI=;
        b=NSpQ3c+7MUVG+iR9s8dhz1v+oVjTZRNrPueOGmZ5rdSQMpth5rGuv5GpS7Ud+UdlwE
         4ivR5sGJ2GI3YxqPYeX6d8/aLt0adzcfNW+6djP4UL62nKe40wUS/ZHCXaF+8hgHiPV0
         jmKlZnziIjw5sjD9vn/hadyQtj4oiM+WeaHHcyQOBc/u6go7rSuSJ5Cyv5uYC3/iWDEf
         Dso6GHcHBb0qw6Ca7jX+Kty0ufCT6jBgMOTUoHx4uQaSu2EfN9PdKRTNcZS/7p96EOZB
         OcVVUKGyh7p47rpw1RPNYoC1EQNm66uOd9eroU711qPomO0uJwuUOsEfpCh50MiAdUVI
         YPXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VcZlzbrT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704966539; x=1705571339; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Xf6Mv5jbMiyEu9sIIXoYI0sxe/3rufhTw/mYj8um7C8=;
        b=mLHdxfWfTUlJQDfW+piXi6X8iehqHby79tW1FQWHT6BZjriwyxp86DbILc5OpKdmsY
         sq2NhpIdiSg31riwS2qPfox6I+okIYNyzypCGH2Uv/psR0f+6MRILZpQHqCJTHGX9hF+
         PRC06bjQ41FggkBBO1jTibvS4FwBEY/5gAmOx05YcbMhHphFcfdppK3DtS7wgV5K6a0j
         CFyUVVRAa9bo7RYYOVY6ooz3kVznQa6hJdmi6kSRklhjeGSeL06GIHqZJULbg5I+thy4
         9zh1+EnZIZFAKY4R2BNapHVNN0cW+phRJJs1+MW1Bu33zV5vw6GQrcWE0GXxL/VLP71U
         F+rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704966539; x=1705571339;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xf6Mv5jbMiyEu9sIIXoYI0sxe/3rufhTw/mYj8um7C8=;
        b=NZlUwOVC4Jk7AsLdlsvJWqxFVhRJ8pfNzvu6uOpOS/siCR7gv5t34eaCHDSkwRRq3Q
         yetUr5E8sy/q5MgauYEaDSZR2iYZ2w5FC2izrKDSBWZA/ZPJHvJaZuxN7os3nnEqi0np
         laYGuV+1UmVARPaR6ESaw84QPDA+K7ru1HtV0wvbj0B6GyHZt+I/tSLz17goKY0+C1N0
         GnbiepTzonATPaNmW63m6S8BnKDRXDPExrlJpc9tvrIAh00/hsGGDRwVXNxfbfAJuWxg
         61pi++2tEivsyFIiLSh3oZ5mjqKYc3WQII6slS65rlyFoRsRrboduAvFjGV1fiVU+nmt
         J7nw==
X-Gm-Message-State: AOJu0Yz23kIVGfxNL7sgMswGF9ld0W0grRz3SjPAd2qRjkugPG24CiLT
	xCvVPQ1PE88Bh4aq5SnqsiU=
X-Google-Smtp-Source: AGHT+IHEk436Qk8UrMgZkMizH4uVYb4Vfj0X8jtVe/se8G9ySJOAxOO85m0BZmpvs3XoFiBfy5JcyQ==
X-Received: by 2002:a25:b185:0:b0:dbe:9eb6:8429 with SMTP id h5-20020a25b185000000b00dbe9eb68429mr867924ybj.62.1704966539219;
        Thu, 11 Jan 2024 01:48:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:68cb:0:b0:dbf:c90:a543 with SMTP id d194-20020a2568cb000000b00dbf0c90a543ls1386925ybc.2.-pod-prod-01-us;
 Thu, 11 Jan 2024 01:48:58 -0800 (PST)
X-Received: by 2002:a25:f628:0:b0:dbc:a9d0:5461 with SMTP id t40-20020a25f628000000b00dbca9d05461mr870757ybd.110.1704966538280;
        Thu, 11 Jan 2024 01:48:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704966538; cv=none;
        d=google.com; s=arc-20160816;
        b=sqipUs0TwSeTyxs/4u8uZmrYh3dDUE/9QjU63wRCt0jU7DiwmMX2u/5W98ZLqYBvqF
         Fe/ig/9qekNXiYrhbRF/RFf3EuMcwZbJFeKdf92Tr1zYfL/0hwGuHP2OVkgDD54X3cuO
         j5cKpGk2NTAiI6CQo1hoDoolHqr234wgdFnbGSR0gesfk3ULrlMZZAn/xncBEnIJLHiA
         gnFzSRMycIskJLix0cIn/+xNhIEkflCBQiiB8NYyE7iAj/0q0x0k8LFg2fssOick4rVu
         RBbEmIhA4Gal09ypma0DvA3dFqe2L5OGEuCf0vDqTWWhsyiVTPSu/cpUALMRIwjf2Z5t
         ygZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eaM81UE8HNBCwln5s5TJQ6eHQuRiuHL2tpn+YpV4pcA=;
        fh=y9FUbJak5C6gzSTedbgzGWVmwnHgqmhZsHaMuLfouUI=;
        b=bAIUeAqchdcVn9gmc7mAla8TrTRTkWiHlWs4oXo3owF1IRv0Ux400EchhzT7N5jvnK
         75lJB7tGZyDyGXt3ErlqczH41QfaBC/p97CCIMXyfjO5j5vtN76AVGFnd8hL/IVuw4oW
         c/AmK6oWpesSL47Jx6NziwVxo/Y6uVaX4dEv3KEcZXGPTxq1LD7QpY4CavE1Ld1/NQNy
         fcaOavat6wmrMBG+i8G7kZVld7ixgs1MGPsZqur5jjl2/vThzCSzHU0fMBNNudb2MOo8
         pm7ol8igudYveD78wc0Z/aFSy7AKQjJxz8S74dBJxzXbJ0mg7noAKRZM0sR08mRev/q5
         NNrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VcZlzbrT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa34.google.com (mail-vk1-xa34.google.com. [2607:f8b0:4864:20::a34])
        by gmr-mx.google.com with ESMTPS id v44-20020a25abaf000000b00dbed7299ed5si48821ybi.0.2024.01.11.01.48.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Jan 2024 01:48:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) client-ip=2607:f8b0:4864:20::a34;
Received: by mail-vk1-xa34.google.com with SMTP id 71dfb90a1353d-4b72377deb0so1549871e0c.2
        for <kasan-dev@googlegroups.com>; Thu, 11 Jan 2024 01:48:58 -0800 (PST)
X-Received: by 2002:a05:6122:a20:b0:4b6:eb5a:ee98 with SMTP id
 32-20020a0561220a2000b004b6eb5aee98mr227842vkn.14.1704966537737; Thu, 11 Jan
 2024 01:48:57 -0800 (PST)
MIME-Version: 1.0
References: <cover.1700502145.git.andreyknvl@google.com> <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain> <87sf34lrn3.fsf@linux.intel.com>
In-Reply-To: <87sf34lrn3.fsf@linux.intel.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Jan 2024 10:48:19 +0100
Message-ID: <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
To: Andi Kleen <ak@linux.intel.com>
Cc: Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VcZlzbrT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a34 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 11 Jan 2024 at 00:01, Andi Kleen <ak@linux.intel.com> wrote:
>
> Oscar Salvador <osalvador@suse.de> writes:
> >>
> >> With this change, multiple users can still look up records in parallel.
>
> That's a severe misunderstanding -- rwlocks always bounce a cache line,
> so the parallelism is significantly reduced.
>
> Normally rwlocks are only worth it if your critical region is quite long.
>
> >>
> >> This is preparatory patch for implementing the eviction of stack records
> >> from the stack depot.
> >>
> >> Reviewed-by: Alexander Potapenko <glider@google.com>
> >> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Reviewed-by: Oscar Salvador <osalvador@suse.de>
>
>
> Has anyone benchmarked this on a high core count machine? It sounds
> pretty bad if every lock aquisition starts bouncing a single cache line.
>
> Consider using RCU or similar.

stackdepot is severely limited in what kernel facilities it may use
due to being used by such low level facilities as the allocator
itself.

I've been suggesting percpu-rwsem here, but looking at it in more
detail that doesn't work because percpu-rwsem wants to sleep, but
stackdepot must work in non-sleepable contexts. :-/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n%3D6vL5YksNsPyqHw%40mail.gmail.com.
