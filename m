Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYWDUOMAMGQEDHIWV7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C5FC65A2A5A
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:18 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id k21-20020a2e2415000000b00261e34257b2sf671961ljk.0
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526498; cv=pass;
        d=google.com; s=arc-20160816;
        b=KbpHQVgISUM9T7wwMjSP3zhimx8gMXIMyS2oWlKPeOa3BO0kRY+EyGf7cOiMDBHiow
         eDIziEuXbP8viAWirrYICODKhsOq5ruALFTZJO5u1Z+0PL9hu/cUq71C8d0gRzay8i2O
         TkvcYLr7JDayusFdUjm0JiMpifFyueZc8DKp0MMut4+VL3BcxY0KR5QExi9AH/smx6tk
         riCCC+9Nm6Vrz5D46lpPOsOKqX3yDqOJPg01r2Y+JrarpsN2/1LOnuuzuAywn2S4j5c5
         tf3x0hQdLgi0wRZrQpGLIU6rxtwiiaFr5OD6MItdDsBcYg5HK5sT7MwcVigb958hj0Bk
         2TKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=V4JCv0PzuPSJz31EZdAjG8ITxk1ml8PrFA243+qfWAg=;
        b=QfnisTwjz1r49AyudrIuCjrIbHXWfFR6wennPKac/Ki9rSTSLezjo1tiMJ0gD+YGqy
         9d/piSJrdBC8tsURxqznkfw10F493LrXZRP1+lwUSbKuugAt+uhrl61nJVRwwSOws1GE
         y44L0Ku1HuJwJ2tN+vXjwFF+BaPNvqOOopNEDCXRQdbURzNPWHL8gty5W37wevC+5b3C
         N7W9Yue/CwxmYyDdQefxheNYz4qk1dkbKkRMHRLBCKhTCFqyvPGLO2nLjoBCSw3Y9bVY
         7VyJXRXxrpYxBxLIU3tiDLjc5kJHkIyFJfBo+Nq3YRA+dKFTbm/FV0+OXMfj4+8Y1H+F
         qocg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aCsHGgV2;
       spf=pass (google.com: domain of 33-eiywykceqmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33-EIYwYKCeQMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=V4JCv0PzuPSJz31EZdAjG8ITxk1ml8PrFA243+qfWAg=;
        b=i+puU5uyhoNQlV2tmdEtKIkpaXOAphck8fmHCxYilyf5NrRP4dnqQ3fgHw1Qll3hz1
         +0EqFRfpbRE60QN+umMCCk3ImJcGhe9sDyleOOrSK8meRjxy9lJZWqUEkX4DrO/rAbYh
         3QoaGlFzyS272UgJ0qDb5wqKvjPHhZulLotWOd/2/gnvp+RKkeySM6q7vYqhm/jqjrMg
         9VLXeiQvRNacko+s0lVnsMXt7ddw41+9OCtb7kEuFKq5uxVISJfDG7xpAdZIDS78UyX7
         Q6p1nGXqmHl4JUP9hBrLm/KzfL29+KpTSjteC/4pzz3q67qLPGzFDipQ2aI+3C6D9J1m
         OnPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=V4JCv0PzuPSJz31EZdAjG8ITxk1ml8PrFA243+qfWAg=;
        b=fk/PrEkHWPRlPQuJjVQXNljEzvViDxa92KyQXY9YKRhuqBjCiV0aZKw3QoBppNPujf
         /1TJEIOEvIfLLc1wmbJJDRt7cxGUi/LSg6CNpXBvPD/HNZYZJ8wROovQ8Dj0fLeWB6wv
         AHXvk/7jSlX2O/wf2XAXNR71iPMixsuBe7KIzDik+pphfVkaGJ4/SEuS6+4efulUrOuD
         gBCqA1E7nOQWSrDjfZ30gssYXKzktrJ93nOSZhN6t4wfLvtQzhJkbr38Hz5HzfHZquTQ
         NUcLE+ilr0b0SCxADUXMOPaGLjAGt4vqepS+92QXuhN0hh5wL5YPlt0WTr0UfUjhhQOz
         YeCw==
X-Gm-Message-State: ACgBeo1LJJc6yz4TPyEGGfhYAMpx3JBu2JjdRp+kx9bt/Wx/W04QiP4X
	2nHKVOgJpuEPrWfu5AGI8FA=
X-Google-Smtp-Source: AA6agR6+d62skFvxR2a/SVV7+KE98ZyPO0k+J3t0UM34QCHtPcyoJvMXoJDc6+99/6GVldwLPSl6Ag==
X-Received: by 2002:a05:6512:318a:b0:492:ba17:b09f with SMTP id i10-20020a056512318a00b00492ba17b09fmr2616062lfe.363.1661526498440;
        Fri, 26 Aug 2022 08:08:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1119736lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:16 -0700 (PDT)
X-Received: by 2002:a05:6512:2255:b0:492:f5b8:ef2d with SMTP id i21-20020a056512225500b00492f5b8ef2dmr2478281lfu.128.1661526496479;
        Fri, 26 Aug 2022 08:08:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526496; cv=none;
        d=google.com; s=arc-20160816;
        b=fIxYDJ86vVLx4bWUjLVsS6TB9gWIcMFuYXF8lXFVSDtF6Astw8/v4WLCB9Uuc7L03m
         xEfOOylNSnFnWzPbgh1/55ItBKZsXaDbJO9f9+l4HIlF7HpaGIOSyKsUkBYWdDB5hp3C
         8tKkGxAmYnXC3dcIB2g6r09M/5rqE0F5kPu3dywuGMK3iIRVPCFkFAnS/PBH3e34j2YD
         qjLKpnXdHu9UlPDQ0GHRrcKOUy+x/zfqfmYLQkxtajoQGb0qSRGAmTtPAHh1f9U9Hs5R
         7vi2BjMLYBqb4fZWCYkBqWyaFELNHDFMbthYOmOfpz9VnqqZHN8ga23lmyI44+Hvnzcm
         fFYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=J3VjO5owb76kN3paB0OLHywjIHrYCcgYmjupWIyAPgw=;
        b=APGKniLiVu4mwx25CXfkyYrBJ/QFdwMYS97YMDnbl/d6le4QMxH3moD9NWWLXbQclb
         4+dWwEbsc2oInOpnb3JGFmkavdbD3ohz8qsGXd943tsgPvhULEKPJJgiK3bosXVgT3PX
         +RcYJGS2lMGM9FfL25FN+8F7MBnSn8PhFW2dfk7JPdvzb8NLMeVEHAjK172c/15CSztk
         NzmXUmaw7jdZJAOlcolwbnXnN4TzbBstOkX3m/FHbjDr0XCCjN6+vRe4cTkk3SqrFebi
         Z1jNsItlFOyORs+ZnzUBc7fgJzp2EOELw4lYV6x7iVNJME74lnF++PhNUGdVgwvodjjv
         kLfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aCsHGgV2;
       spf=pass (google.com: domain of 33-eiywykceqmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33-EIYwYKCeQMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i22-20020a2ea376000000b0026187cf0f12si74854ljn.8.2022.08.26.08.08.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33-eiywykceqmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id h17-20020a05640250d100b00446d1825c9fso1229991edb.14
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:16 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:aa7:c611:0:b0:447:844d:e5a2 with SMTP id
 h17-20020aa7c611000000b00447844de5a2mr7350187edq.10.1661526495846; Fri, 26
 Aug 2022 08:08:15 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:24 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-2-glider@google.com>
Subject: [PATCH v5 01/44] x86: add missing include to sparsemem.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aCsHGgV2;       spf=pass
 (google.com: domain of 33-eiywykceqmrojkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33-EIYwYKCeQMROJKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--glider.bounces.google.com;
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

From: Dmitry Vyukov <dvyukov@google.com>

Including sparsemem.h from other files (e.g. transitively via
asm/pgtable_64_types.h) results in compilation errors due to unknown
types:

sparsemem.h:34:32: error: unknown type name 'phys_addr_t'
extern int phys_to_target_node(phys_addr_t start);
                               ^
sparsemem.h:36:39: error: unknown type name 'u64'
extern int memory_add_physaddr_to_nid(u64 start);
                                      ^

Fix these errors by including linux/types.h from sparsemem.h
This is required for the upcoming KMSAN patches.

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ifae221ce85d870d8f8d17173bd44d5cf9be2950f
---
 arch/x86/include/asm/sparsemem.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/x86/include/asm/sparsemem.h b/arch/x86/include/asm/sparsemem.h
index 6a9ccc1b2be5d..64df897c0ee30 100644
--- a/arch/x86/include/asm/sparsemem.h
+++ b/arch/x86/include/asm/sparsemem.h
@@ -2,6 +2,8 @@
 #ifndef _ASM_X86_SPARSEMEM_H
 #define _ASM_X86_SPARSEMEM_H
 
+#include <linux/types.h>
+
 #ifdef CONFIG_SPARSEMEM
 /*
  * generic non-linear memory support:
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-2-glider%40google.com.
