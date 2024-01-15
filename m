Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFH2SWWQMGQE5SFJW7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C98B582E035
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 19:44:37 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dc21df30950sf479512276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 10:44:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705344276; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5fSQtbUPFQbeQui8sC0UkGMaaEvwWnrqMnbEhM0VQYp9ZxaXZnzx/6uZKijd/wEQm
         z4qqSSo1qlxIpvLp+m7hIZ0kffCo4/nqHr7s1LCXtoFBVkicS5f/DFGq9okZXbHAZSA0
         0S+OG9IyJzIR27/6XbE2GQMfejlBpCCaCG/ws+fRRjizw4sHgfczfVhsYXFLQMKLytEs
         ZwpzEZ+nqx8pKpLzxNo7m/kVdL8/kumEmj49GxDTPLV5vERvC2HaXti33O+EXxce9IM3
         3CBcHeHQvPchKwWVPsU6ELi5G4mdcU4KU+m79rMKnla86WKacnuh+9F5GNkOEBxs9Fex
         lE0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Iwah+yZwazEmp/BQqucDNQP7GjDTVB2+bG1WBseCQOs=;
        fh=vDXYjwoeUW56nDCk/K9T+9Sqpx0GLahjZYZH9iPImH8=;
        b=RiReytms6pqIJww62m9ftR4vWZo92eGyzzO/4pZE6r1U7DbxaDXZeKKBcmTGe/0KFp
         ejJk+m1hfbuuJ3u9HwklDYwgyx4YRSprfHjgighfqcjkxoq7WwgzQPm8Lp/uRmqqepG4
         AQiIG3t1+rZ95JW4IBTkgXb9P7BDt3LOAQeN4awM6QZYVmpjgCVif5f67ieL6rRHZ3pq
         adFw86mqUrCU8lM8iAX07EFSSq0QqLQhztPUZO32fR6yWJMjrvpikwwNgMTTl+IM4347
         RTxODVfMD4yQTOpYaPvqz/HKCJa9a3TsfFqmj6hT4UIXZ9jtS1arqZgMdIQ90AauKeC9
         BZxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBAYqQMC;
       spf=pass (google.com: domain of 3e32lzqykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E32lZQYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705344276; x=1705949076; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Iwah+yZwazEmp/BQqucDNQP7GjDTVB2+bG1WBseCQOs=;
        b=mh4+IMbxDX1OdVqydjIf7gKb0NPnHkM4uBtrfKfriHTCUQRe0tlk95RudFqQhBhjuq
         MTRujGtrfMouY+clYjtrempykDz2MWhCiHNn31u2a2zQsS1lemFQLjjiVCI2LW6vyYMM
         n49I65xdwKGLX+nzovlA05SfD0wZxdo60zfbkPTArm/XOaVDkoa+kqR1GBid4s4TWnYH
         i7ls5YgBYDw761xs9mDHFhMr7JBfZNnxJh75vEBn6N3iL+yFBx8bn0wO9MJ7XpnxlEd9
         Gzh+U4J1c56wfurvVov4IbiJ63HNAKT8dnrVGp2RQAvdhXYbyLOI91Ccy33ssFySGbGA
         JTOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705344276; x=1705949076;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Iwah+yZwazEmp/BQqucDNQP7GjDTVB2+bG1WBseCQOs=;
        b=q92GpA64hm9YSKHx99smko/GrjdMFdBdHdXWM85lOI8HMKMnnonxFq6MVnSQ7Vw6+u
         HG6I2OJ83dNwvktVcl2lZHaGak/M7qZlNGYTEDZY0zAgLbFgU3fs96DpBwXihoBv6GA4
         rjXLGTsNIrQMnEA+IKONwNUMC88k8xYyKwtPukJRcD1A/PlkU8md6H5wTOLAAhJZvwaQ
         5Y5cPrlGBN46wW4HkEcPkEv/jY62cupnjBb3iIP4xj4KS4F8K7teH9mlASpxsXPdtnOl
         t3mz1K7YN7wyHyHKk6yNSm7p6Ma3EJSoLo7ML8SJWoEwra7LrSqG7r1g6cJkUDP3j2Sd
         P/Kw==
X-Gm-Message-State: AOJu0YxZLN0RU31d4NIbuNOA03hDgcFKaN/KfLA2Y+de1h3vWIsvnw6M
	dBt1vxPQZcINcRew05hx8kE=
X-Google-Smtp-Source: AGHT+IELQgjSX6yxyh1Zm6IDLpXVDm2BykLCN/5U+PncPhN2bWWbVNZxDNxJwTRIGfmZHUnJTIjmfg==
X-Received: by 2002:a25:9d03:0:b0:db7:dacf:ed90 with SMTP id i3-20020a259d03000000b00db7dacfed90mr2613337ybp.113.1705344276490;
        Mon, 15 Jan 2024 10:44:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1007:b0:dc2:166b:1a88 with SMTP id
 w7-20020a056902100700b00dc2166b1a88ls597167ybt.0.-pod-prod-07-us; Mon, 15 Jan
 2024 10:44:35 -0800 (PST)
X-Received: by 2002:a5b:4c8:0:b0:dbf:54ff:29f8 with SMTP id u8-20020a5b04c8000000b00dbf54ff29f8mr2308729ybp.107.1705344275637;
        Mon, 15 Jan 2024 10:44:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705344275; cv=none;
        d=google.com; s=arc-20160816;
        b=ucazezde0KE3qsQPJpQb0cOsZZKeW0pZ9iZ/mPq4P1Th5D8Y0ov0TOwm+GXL6zJ2OV
         G8CC5/dyrLvcnSa8uhdznjx/pBAyzWeR9+80eWAW4qeR1o65gAwrSL8a2P32FRl9KzsW
         Ge3lc+84DYZPMHygQB5NL7lMuQWaaJEyUk8Tv2QrGGwUYhGqoogXoCJzonGog91QH5bm
         Hq0cyCEIjUjPWk7OAY6w6v1t0Ygw06B0+2wQ3tRA13GctLrSBgJLYL+lZ08qm8AMGk+y
         UASJMeVM1yZqBbhg3DUkxslKO/RxJf8j9pV2f0bogBOlqqocIrkQQh/zZ4PUXsy0W4Do
         syIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uCCPLj9WIEdpIVdqzT004aXc52PF8jQhxejOjNa7h3c=;
        fh=vDXYjwoeUW56nDCk/K9T+9Sqpx0GLahjZYZH9iPImH8=;
        b=gNc8WRiPpMVvslaYGzWCbZK8/lfc69Y9OxLxgPbXqUYAp7Xxz30yYSwfgPVWozFunc
         qvhTvgW0bLiX5kXPfo9wMLwhwnObmnl4DKtSjJdtAOAa4jIMnDoPOFvFrgPVJz/ROQaF
         S7muJ2t/OiAPIixhzBm77dXzA5jBF1iqhr+ewb4d4z+Spp25m+CqO/9BDEQbbHNTvkZL
         8VizQK+BppDSZOQ27O+Q26VF9Ls2IZbVM772ulw6alZHvojh9BCTBOasPaMGImtb1sB7
         SbPTI+80LyhxraCTJVp1+AmNOcP6I2Vb+ijNZoZCOJ8WfGnmTVY0ipGgnx2J9p+e+V6E
         Onvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBAYqQMC;
       spf=pass (google.com: domain of 3e32lzqykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E32lZQYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id 184-20020a2502c1000000b00dc21a14a88csi97556ybc.4.2024.01.15.10.44.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jan 2024 10:44:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e32lzqykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dbe9dacc912so10603577276.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Jan 2024 10:44:35 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:c671:6fb:2d64:ae58])
 (user=glider job=sendgmr) by 2002:a25:5181:0:b0:dbe:a0c2:df25 with SMTP id
 f123-20020a255181000000b00dbea0c2df25mr268706ybb.8.1705344275329; Mon, 15 Jan
 2024 10:44:35 -0800 (PST)
Date: Mon, 15 Jan 2024 19:44:30 +0100
In-Reply-To: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com>
Mime-Version: 1.0
References: <1697202267-23600-1-git-send-email-quic_charante@quicinc.com>
X-Mailer: git-send-email 2.43.0.381.gb435a96ce8-goog
Message-ID: <20240115184430.2710652-1-glider@google.com>
Subject: Re: [PATCH] mm/sparsemem: fix race in accessing memory_section->usage
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: quic_charante@quicinc.com
Cc: akpm@linux-foundation.org, aneesh.kumar@linux.ibm.com, 
	dan.j.williams@intel.com, david@redhat.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, mgorman@techsingularity.net, osalvador@suse.de, 
	vbabka@suse.cz, Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Nicholas Miehlbradt <nicholas@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nBAYqQMC;       spf=pass
 (google.com: domain of 3e32lzqykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E32lZQYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Cc: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Cc: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Nicholas Miehlbradt <nicholas@linux.ibm.com>

Hi folks,

(adding KMSAN reviewers and IBM people who are currently porting KMSAN to other
architectures, plus Paul for his opinion on refactoring RCU)

this patch broke x86 KMSAN in a subtle way.

For every memory access in the code instrumented by KMSAN we call
kmsan_get_metadata() to obtain the metadata for the memory being accessed. For
virtual memory the metadata pointers are stored in the corresponding `struct
page`, therefore we need to call virt_to_page() to get them.

According to the comment in arch/x86/include/asm/page.h, virt_to_page(kaddr)
returns a valid pointer iff virt_addr_valid(kaddr) is true, so KMSAN needs to
call virt_addr_valid() as well.

To avoid recursion, kmsan_get_metadata() must not call instrumented code,
therefore ./arch/x86/include/asm/kmsan.h forks parts of arch/x86/mm/physaddr.c
to check whether a virtual address is valid or not.

But the introduction of rcu_read_lock() to pfn_valid() added instrumented RCU
API calls to virt_to_page_or_null(), which is called by kmsan_get_metadata(),
so there is an infinite recursion now. I do not think it is correct to stop that
recursion by doing kmsan_enter_runtime()/kmsan_exit_runtime() in
kmsan_get_metadata(): that would prevent instrumented functions called from
within the runtime from tracking the shadow values, which might introduce false
positives.

I am currently looking into inlining __rcu_read_lock()/__rcu_read_unlock(), into
KMSAN code to prevent it from being instrumented, but that might require factoring
out parts of kernel/rcu/tree_plugin.h into a non-private header. Do you think this
is feasible?

Another option is to cut some edges in the code calling virt_to_page(). First,
my observation is that virt_addr_valid() is quite rare in the kernel code, i.e.
not all cases of calling virt_to_page() are covered with it. Second, every
memory access to KMSAN metadata residing in virt_to_page(kaddr)->shadow always
accompanies an access to `kaddr` itself, so if there is a race on a PFN then
the access to `kaddr` will probably also trigger a fault. Third, KMSAN metadata
accesses are inherently non-atomic, and even if we ensure pfn_valid() is
returning a consistent value for a single memory access, calling it twice may
already return different results.

Considering the above, how bad would it be to drop synchronization for KMSAN's
version of pfn_valid() called from kmsan_virt_addr_valid()?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240115184430.2710652-1-glider%40google.com.
