Return-Path: <kasan-dev+bncBCT4XGV33UIBB36S7PFAMGQEFXCKTFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B9AB1D005FF
	for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 00:17:04 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-8893be16bf2sf6785596d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 15:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767827823; cv=pass;
        d=google.com; s=arc-20240605;
        b=dO9iLr0J7tpvCbho1a7Z8W0agmKuIf7Sq46EYlx0U3SN2S+QNl96NFPIADGKa/Xt/+
         sPCnBhT0HaMiR8afOMGi5yunp+dgkxi8vXtmiugPb4++UsQH/+OX0wXAKn/JDyUuwioA
         qLjxU4iwobf9/6X+XmJvo2Mh1mKAULFQXe16klB7DK/RxbKb8uHh/FB5hvk+rNuCRRO2
         a+iJA7qNlP5SNq5JPeplo6hzbbvm/N3Sbx6B6EJKaBGPBC1h8HJqtENLCpxkfxOOiZYl
         D3FjMsMAnxhdbsYkiuAdnA8p1+JrYdj/b3uXvgEGzUhBvWhya1TZdj8ldGc0Qc5CuhZH
         4Pfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kbCVe9GCL8JmavdUH2bD+5KnogdLAq8EPxwqIlp6/Xc=;
        fh=p7ER0NOhiOAhXProQoFTOE63aOW6agNaDOPk2EsyfPw=;
        b=iT/U3UzaO5TrgLl9MVFyuWJUDnudIdAZ/rOOB0BHP+0SbX6+h0/VDct7ae2/buET2F
         jCqrB95jobyG/cXSZo6LTCdasdVli6tT0DbvbS/JiyNn+fz86EGk+yk3BfJu5NS43hLw
         OX1/dat48ajmIltGEuKr8lmNNLUxgCe4ziotP59hW3xh/wZLKmhDi+yAVyx5FLHccDKg
         odJuRFpyXBC1O7XyUt03Yudk7l5n4uhr9MK1VL9Y4UAFMXzRX+dqdwHkaEZIWkbwH0cV
         yXDXxcJX6wup3nPTWdnk2uDs6oZ3lpbb6JQGwJ56xSCuO5s5WkC7l0U13F9iheF/huNi
         Gncg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kPXLC1Q8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767827823; x=1768432623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kbCVe9GCL8JmavdUH2bD+5KnogdLAq8EPxwqIlp6/Xc=;
        b=vH7uNbChRMbKjEj5cHTxFGo/mlXVgakGOLenJ/ILFbiX8qZia5hpGDsKmq5n9p/6+y
         7LAOyRGR5qkd6aU0P+2C3Wc4FDUnRHYp5JrOY9MDefMwxm4OJuqhXAY5ZH2cgA5f7AyV
         bSFURsm49nCkTb+azfkLF+tu/XGNz8LnMniJ1N1i6zaPFdydVoyDh08cUf32sukcwoD/
         X6xo1QLrm7vnNzS/5o7SQCSUT/LRrXRlVe/1dj/TcEKzSU7rH5lANw98DPQk2ia9v2HE
         d58Tt2fGqu50BDCzFvg9s2lIPxZ0yjuGUdySL/NQRkWuS+GRzUqzhg8z48akHTpoonwb
         zJRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767827823; x=1768432623;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kbCVe9GCL8JmavdUH2bD+5KnogdLAq8EPxwqIlp6/Xc=;
        b=UxhU7Itz4wCdSZngsFLvSBHRbNUDwVOcGFoxedurknX3a+U1C3dSSWODHY8dsmKBMa
         vrrz146Z5ylI+b6mlttxsZaZo5NlyVRUNWEnX8djnlkYtpKY0XbgeB/6VFxqTtlegv0G
         or9W9fl6m1zqJ8N+gxJIwreLRuO0qSc98XpLaSsfrN/N1w4NhlgWU1GTr7fvIvZ2tJ+d
         Fc+OagQzdQjKNIyhT+TavbK8jLmyDnvxFESnXm3mgaOdD9eTILm11FylVrDqY2tlRtkZ
         zq7VDwBj5kb6fV21tCEvonrd+RETmiGO7nXmpZczms3Uf2EYtgKl6tgIycI0tRaCIe/r
         Drxw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvjNJlnw6uok0Fq1n5gXDEvntAxSO30j5snlyDNl0Dh9oYNAVWBAt5eyTaSAbpg/edS4tYwg==@lfdr.de
X-Gm-Message-State: AOJu0Ywm2lS0bqquIqFcZ9CKi+sYrPEHnJVevnJkw7Fiw0n/CBqQQjQE
	UVlyt8OHi5jmKQ8dxcTblTgeyJrS8SiHJoPntBLMqMI1xxhE1THRjBMi
X-Google-Smtp-Source: AGHT+IEZq23jHjLiWVjuoGr6CxvDVNa25lDePs6yl+lIky99Wuo/woqAZlY8owc3R7nVRdufnEFk+A==
X-Received: by 2002:a05:6214:234b:b0:88a:529a:a547 with SMTP id 6a1803df08f44-890842a078dmr48588316d6.6.1767827823368;
        Wed, 07 Jan 2026 15:17:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZe6HW2+gyo/i6pkgcHfXXLkWOgeqY4jcm7om5sCDotgQ=="
Received: by 2002:ad4:4b2e:0:b0:880:5222:360 with SMTP id 6a1803df08f44-89083e09139ls11936556d6.1.-pod-prod-00-us-canary;
 Wed, 07 Jan 2026 15:17:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXDZT/iPzza/cT4OP3dI/XXoeyZh37YPFje49Io4tTVkj++p9x9eAbdRNePYFHT8EvMaiBpAe1oUvM=@googlegroups.com
X-Received: by 2002:a05:6102:32d3:b0:5de:a2d2:8076 with SMTP id ada2fe7eead31-5ec752dbfd5mr2848374137.0.1767827822538;
        Wed, 07 Jan 2026 15:17:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767827822; cv=none;
        d=google.com; s=arc-20240605;
        b=BKOA4eIo3HcLI1+zGX4Buqdzz5j+ewyRQwy+Ar6ShOgyP9VBLXReriDpFRRHBmyJwP
         AlfIfL7ZKljMHVV1vf+8VPTBhM9i1j2xRAo76a3khTwpU2C1eSzZ+1i2m/B3tUk+KSX8
         CqO7PVznHtmqTq58dHTTPX1gg4K0eq4VZRLwemrkcxiJZHkCFcP2M9/cutr4/nS7J7qM
         AkbMxnd7cE2Ya4MDvZrDusXG16RcwMgCtj5xuAp2m3vC6cVt2+CqoeEGwP+bfDbVaahN
         uS0LKd26pYcDW7FUzN/rx5PqA7yXF96I3QweDFFv7Foo2ux+J2bwkJglgsH8/uGcg0G5
         pwKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Q72+EIdIzqEe2w7lUusPCf29apkjVSTshTVgfQcAU/4=;
        fh=i4cXANmOkcI1HdLP3jEhJ1bPnodUy4O33muA9pG7mpg=;
        b=M4emmwefKtijHvu9erDtYuktflaeJFB5uz/WS5cC8ewNaV2LSp+W3Pkv9OfZ4ptEjY
         7rjdPywUKgidVmsVu289k87or1WbdNsmBzI5YLYLr3tLZ6F0t8loGQfhBj8sGCx8GG5t
         0SJPZdDzk4qu7yyy6+Y9b6sbHRYM0VlB3gIWumC53hbdiFFuDc2kJwhDY+/20DKESXXm
         4iCMf/V/ZWUt+93Xv8Va7G9/qfLDZMDvmkYULo7TLmoKB1J6hhaV0pLOM2ORcXHYN+q3
         mY+IMXLgcpCUN0e++Q5xh3HUzmstATc7V6EZ0P0W1ySbx7+rHnFEQqMhXJJHhkN/iV3x
         LSpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=kPXLC1Q8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-944135fc6b5si313844241.2.2026.01.07.15.17.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 15:17:02 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E33DD60007;
	Wed,  7 Jan 2026 23:17:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2B315C4CEF1;
	Wed,  7 Jan 2026 23:17:01 +0000 (UTC)
Date: Wed, 7 Jan 2026 15:17:00 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86/kfence: Avoid writing L1TF-vulnerable PTEs
Message-Id: <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
In-Reply-To: <20260106180426.710013-1-andrew.cooper3@citrix.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=kPXLC1Q8;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue,  6 Jan 2026 18:04:26 +0000 Andrew Cooper <andrew.cooper3@citrix.com> wrote:

> For native, the choice of PTE is fine.  There's real memory backing the
> non-present PTE.  However, for XenPV, Xen complains:
> 
>   (XEN) d1 L1TF-vulnerable L1e 8010000018200066 - Shadowing
> 
> To explain, some background on XenPV pagetables:
> 
>   Xen PV guests are control their own pagetables; they choose the new PTE
>   value, and use hypercalls to make changes so Xen can audit for safety.
> 
>   In addition to a regular reference count, Xen also maintains a type
>   reference count.  e.g. SegDesc (referenced by vGDT/vLDT),
>   Writable (referenced with _PAGE_RW) or L{1..4} (referenced by vCR3 or a
>   lower pagetable level).  This is in order to prevent e.g. a page being
>   inserted into the pagetables for which the guest has a writable mapping.
> 
>   For non-present mappings, all other bits become software accessible, and
>   typically contain metadata rather a real frame address.  There is nothing
>   that a reference count could sensibly be tied to.  As such, even if Xen
>   could recognise the address as currently safe, nothing would prevent that
>   frame from changing owner to another VM in the future.
> 
>   When Xen detects a PV guest writing a L1TF-PTE, it responds by activating
>   shadow paging. This is normally only used for the live phase of
>   migration, and comes with a reasonable overhead.
> 
> KFENCE only cares about getting #PF to catch wild accesses; it doesn't care
> about the value for non-present mappings.  Use a fully inverted PTE, to
> avoid hitting the slow path when running under Xen.
> 
> While adjusting the logic, take the opportunity to skip all actions if the
> PTE is already in the right state, half the number PVOps callouts, and skip
> TLB maintenance on a !P -> P transition which benefits non-Xen cases too.
> 
> Fixes: 1dc0da6e9ec0 ("x86, kfence: enable KFENCE for x86")

Seems that I sent 1dc0da6e9ec0 upstream so thanks, I'll grab this.  If
an x86 person chooses to handle it then I'll drop the mm.git version.

I'll add a cc:stable to the mm.git copy, just to be sure.

> Tested-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
> ---

That "^---$" tells tooling "changelog stops here".

> CC: Alexander Potapenko <glider@google.com>
> CC: Marco Elver <elver@google.com>
> CC: Dmitry Vyukov <dvyukov@google.com>
> CC: Thomas Gleixner <tglx@linutronix.de>
> CC: Ingo Molnar <mingo@redhat.com>
> CC: Borislav Petkov <bp@alien8.de>
> CC: Dave Hansen <dave.hansen@linux.intel.com>
> CC: x86@kernel.org
> CC: "H. Peter Anvin" <hpa@zytor.com>
> CC: Andrew Morton <akpm@linux-foundation.org>
> CC: Jann Horn <jannh@google.com>
> CC: kasan-dev@googlegroups.com
> CC: linux-kernel@vger.kernel.org
> 
> v1:
>  * First public posting.  This went to security@ first just in case, and
>    then I got districted with other things ahead of public posting.
> ---

That "^---$" would be better placed above the versioning info.

>
> ...
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260107151700.c7b9051929548391e92cfb3e%40linux-foundation.org.
