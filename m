Return-Path: <kasan-dev+bncBC7OD3FKWUERB47JUKXQMGQEYB2QVTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BA8B873E6E
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:24:53 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf121575ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:24:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749491; cv=pass;
        d=google.com; s=arc-20160816;
        b=A4OZaMihmkr69hEAqYMKMkjHPRgmzfP3jBYV1bud0xoZNNnqYRFMgegFQnatNmBK9d
         CPdaHD5LlE6miHFx5E8j7PbRvixP+WENlFKZfNBs/NiKckZvgPGiWnPF9JuzaDJDyE7W
         fFFOgRmu2Ny3pmHxK7WJ5Vmg74cjqZZvUgbLEytlLshD375kFz8cfrzJh3CmzUNMtsB7
         EuSHkLX+RopHtaeOEspOAoI61vpVi+oWwfKJ1JmM8kQca/gk/ikdadsMcE3wLR7jxbEu
         yRMQdPceIxn3BXASCxcQvjH/pEOKwsl59+2mIO6lQsZHzt3WOJs2emqbnrIXnM0L8p6S
         7WKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=9n9EAG0JnOWN438p5WbrJQU+jsjPVQvtkoJL0uCAH0g=;
        fh=NFjb6ivXwq4TigB/Q4ZvYyphG+BNL7AtALJPaziw+mk=;
        b=eeRHKswIALij4wyrHIPsBIiJs7Fuyz2vl6r96ox3TCgdElhCAP3y3wg+yU2gVhb2Od
         kLLdC6qaOv2bBdxBvXDZEk1NuyXixy5Pni1zf6i6zW2MzbPAOvoLZzSYfitkgo7qBUqA
         iYO0MRYgnwcT/X6RPM7g2jd4CWz4JfQLKbnampRaXCu780XXcTJeqF/W3RMf/IPAaknf
         kyHfgv92OgwS9mjS1qIk2P6QG5VcgBHyLtOrNIZBE9Xyatlyi2pSJLavSov+E6vPfMI1
         ti7dqSATGgmc8ERJNbK0t88RjmWMwL3Rf73UTYhAdLIWXpnDb/QxvOWQTXyzelikkH18
         3CiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wQo+k7yy;
       spf=pass (google.com: domain of 38btozqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38bToZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749491; x=1710354291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9n9EAG0JnOWN438p5WbrJQU+jsjPVQvtkoJL0uCAH0g=;
        b=PA9bgG3KRZ9B8Ird1tb7ZS8o6IdnCtKip7PTJTantKaJkWZ/pucpd3jB3MhO/kWklV
         Xwl5AnmxjfADOtt/s9DZm9dobA/hISQU2eIPmyQzZaQFD25x6GwkRH/anI3lRBcf8X3v
         p/7VsdFc1x/2SnY9NMd21R/YKFNeOznUBwpn34epSLaUGlRU77PJBy4HsAtHDg3K3FVX
         aTpkvBNicHGrlDL26/VHW96z6oOvgZIjyg2X+u7eSk9DSKr/MhdmkdsqhCL1dhKju9PL
         Sz/SiEqjx4eD81WvgC3a/q+nHEHQw+bu6XH2YjLyFxiMY/M+nf917M1MZ2DgbkT72ZQs
         bCRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749491; x=1710354291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9n9EAG0JnOWN438p5WbrJQU+jsjPVQvtkoJL0uCAH0g=;
        b=cTSIUGoq/2i4jtmoCrYK4LLKG3/tG6OyNrbvBQQL0YvvJ6inMYAqD7UgVXSrtlCRYe
         VJ/fJHoEd+DUodKmulu3ClgWIgCu37Svqp7FP/hjT1k0kKMp63ayXjSYtnq87kkJKy3S
         +uJzOs2YngAQI8a7wsCJdrCUkxG0sm4L3MPGKHGv6LIOEQ3QX1sG2NQHKECEeM7u2ips
         UQUCsR7ZRCp4vMGfRZn6ywRgSeKEq4jaFNC8wyK/C6kWvg6k2PwqTLQCPjYNKvAD3+pD
         iDNc3cigYiqUVOi0FCGlPlv0PTXuQQ5e9sKX3QSu6+daos03f2yliLFLluwoiqlHTzEU
         AsAA==
X-Forwarded-Encrypted: i=2; AJvYcCUvFAYj7JQtOXRPHLGpVsrhU9C8Qkqisup6Yag8aZBDTvir3gJDWNyz9BA818nl8HUDmI4b3MgzLf5DkbtbKAaW2so/l3mg+A==
X-Gm-Message-State: AOJu0YzgiHSvv2H4So/DnXpCIXyLP6KvstN/Zf+21r+Cyju4U5KlJGr/
	dwr5zvdKz1RNfyGhd5ue89cR8RbgzPmsbhChAexDuKD2A6OoIL8Z
X-Google-Smtp-Source: AGHT+IFWbxMbYVccwdM6aypZpPkTZldNL/KHLjrcAPpxOotrjwdcmixQyexcY5o6xd+LWXM2LQC10w==
X-Received: by 2002:a17:902:988d:b0:1dc:7721:94cd with SMTP id s13-20020a170902988d00b001dc772194cdmr41200plp.23.1709749491384;
        Wed, 06 Mar 2024 10:24:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:8915:b0:21f:e033:3f23 with SMTP id
 ti21-20020a056871891500b0021fe0333f23ls77650oab.0.-pod-prod-05-us; Wed, 06
 Mar 2024 10:24:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVi9KXYLjXtdGmRIODPHuCF9QB3M+s32mvXtnVz0Wsg70sJaLMuxBvrfC1rn6afrk08cQix9P1GOkCuIQYYd0OPkzMTIGv67WMwmw==
X-Received: by 2002:a05:6808:150b:b0:3c1:ab8f:1745 with SMTP id u11-20020a056808150b00b003c1ab8f1745mr7542435oiw.23.1709749490377;
        Wed, 06 Mar 2024 10:24:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749490; cv=none;
        d=google.com; s=arc-20160816;
        b=QG+4RG1Bky9e9NRpVQ7kRevkCtD/YbpYJ/uWr6V/W74mDVj4R4uQDTokCEqFZX5Dmc
         qJ9T8VJp4poNKOCX5bbIxDdLvQTqDvSCTPM2bmxnEaxbxIhMBplbtIwLT8s+DYY/gjFe
         m7b1rlkahcHWHb+oOw5JmRo5IIMA0kbld8Y9FZv2bz0HP5s99XkW9vH/nFGNhZeT3Dv7
         ugYoKcD8xFw0NB/Tw/9lOA3Kz/2IxwzRJyRsbzwd6K2BfLbM5rb/LeQGbWamnN08GS1B
         g5tp3DEOD6t0+9vIx5HXqarfLkDxQL9U93UEHqN6Elsql5YDEvvNh6FejsHqvuJrWL/n
         NITw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=IB/ApQiOXGBR0WmAItdSsQq8CBMweolDZikHX0/GsD8=;
        fh=S5Xu+MEUiUpruK2yB5tgXcxx/7o1oOS6z0B+iuZS6zw=;
        b=JUgFJK242VLfPNbMGZrk9YIzp2HgHEPi46v3i16GYqI5ArRBLm0quZA1e3OTHKpKHb
         mhGZ4B6L4HeY33/O1i8w4sssTpVyLYL24vFG5o5hxPGUG3P7AkaZmVVMBILNIGchs0cj
         gg34Tz6b/NZEIGlYfF52YHlcAivEZaKLCBsGCHVdF4D4NQPK5NLnautIK8Jbtrp5sLUR
         NRHj/PQRwGG6qZOL469x5D0d+C6vndL5fpeNfgZnxPSrYp9dlUoCB6w+l5NAEwq3h6fr
         HHzIxRx/gA3/FP0rvzQqnzg2gEW6UP32YjrJNie/wtg5wu+hvvInnyOGD6r35nQRtzaj
         jTlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wQo+k7yy;
       spf=pass (google.com: domain of 38btozqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38bToZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id n187-20020a6327c4000000b005dc851134acsi1386177pgn.1.2024.03.06.10.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 38btozqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5f38d676cecso15098997b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVfV8IEZEqckInL7LbGVQ+qWPOTl1ZJYOs0ASimUSzhb5+/E5PNSqlyQfMoVZfq7bv7PYJq2ewf1UAQ3NyTde258lbJGvlLogJkYg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:110c:b0:dc6:e884:2342 with SMTP id
 o12-20020a056902110c00b00dc6e8842342mr1897962ybu.5.1709749489247; Wed, 06 Mar
 2024 10:24:49 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:00 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-3-surenb@google.com>
Subject: [PATCH v5 02/37] asm-generic/io.h: Kill vmalloc.h dependency
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wQo+k7yy;       spf=pass
 (google.com: domain of 38btozqykctqikhudrweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38bToZQYKCTQikhUdRWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Needed to avoid a new circular dependency with the memory allocation
profiling series.

Naturally, a whole bunch of files needed to include vmalloc.h that were
previously getting it implicitly.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
---
 include/asm-generic/io.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/asm-generic/io.h b/include/asm-generic/io.h
index bac63e874c7b..c27313414a82 100644
--- a/include/asm-generic/io.h
+++ b/include/asm-generic/io.h
@@ -991,7 +991,6 @@ static inline void iowrite64_rep(volatile void __iomem *addr,
 
 #ifdef __KERNEL__
 
-#include <linux/vmalloc.h>
 #define __io_virt(x) ((void __force *)(x))
 
 /*
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-3-surenb%40google.com.
