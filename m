Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ6CUCJQMGQE5NAJCFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E915103D7
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:24 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id cn27-20020a0564020cbb00b0041b5b91adb5sf10595459edb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991464; cv=pass;
        d=google.com; s=arc-20160816;
        b=klWnDethMp7jaJQNsS3PoxL9InycQ7ZVtPz7LUzfZmk1BT0j/RTvbKN4J/7uRICYjb
         oPrlsIajNL8gj8vupN3YkyMuAYcvyHp0PW+ApTHoHFtNpm2U7tFVhFWcytbH82ucWLIu
         44NUmyNQvo9zQqcvm064WNulA4DAi+i7NtfOC1+PWMawXwZipC6b4EAkEaxV044+G2u4
         gLSxc4aGtNgA7ycSqLlSwDBPBlTL7J2dTpPZG1aHXAQe4JKE7/3TtwwgoS9squuM4xr7
         kXZnJQqb2UD4mzAULFG/wbE9+3jSoj/Cche3qXkzO8SEFPPf1qE0Af1WljR8kI6o3W1s
         MS6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=b1lYaTXGh1GyjCNBoiPjjeC+O5gig0O9lL1b0ALlKgM=;
        b=aqlsIjNsJAnIkXiJpwTNQd2E3DY8q545qqlcgEcUTd/iztYozhlb+T7xZFvqyTnGf7
         QO0Fb/0rbG+6oGhM1m3JAVLdYuXMmGhaqjqTLVhn2DMBFBvH7H0xZH5Az+c3+Lx6jS7T
         oRqT4iKgNQ11j2miHB1L6T8MXxSYdU+fnK5TieTTRx460Ljtgk7ykMweORo3j7sP5wjB
         zySYF+vx8q7J5NyNOZC6ZdZGUnUdNqwh0YeMjbuF0xisBYWhVQhuIhCTpHtSJyQ0iKfN
         9LslB1NpeNsSEVwT2LZSldR6p2wN8xte8kOXeo6rDYe7rF/vvKdRHAbfMijnS4tQPsAD
         AG3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ev6F5DoT;
       spf=pass (google.com: domain of 3zifoygykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZiFoYgYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b1lYaTXGh1GyjCNBoiPjjeC+O5gig0O9lL1b0ALlKgM=;
        b=CUzviiZQ6LhhQt3a37mlfBnKX4jXeVjJzYQobmbvOprJXK+b93uHsuQl+CSzGr8FH5
         GuWVssZooFrVQxZFgF3F1VUpx2uV+dvM+wcbzjrcnKwwrVBQYlp6F1IfO/2tCziCAGEg
         AOXzMkow55pE/rKmjY7j9Yu3rRWOE4tjvbOF2pDdUtQn0MNYVO6o9BrDo9t6Db0zcBtY
         0GVxvuBolC11FTQ4PfgLOryXwWV4diEedeqacJl7Ra5ITlv53qcduKEFGWb42fb451ty
         6+z0FtSSmKyLliFImUmAK7n/w1jyQc2zxe9n7AD4Bp3X/xSXFW5pWrGS8mpAtUK31Dmk
         j4vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b1lYaTXGh1GyjCNBoiPjjeC+O5gig0O9lL1b0ALlKgM=;
        b=HByCnLfA+c1lzzlz10Gz9OnSw0O3ouFE7isQEuFgNvLs/r1AW5kP1NCNXHgIArlD26
         X6IisCPNYTiUtGLuyps+AosUzFJ9ruED82/C+X8tvJJLcKB04m4Amem4KPcPBOd/cYmx
         161T0g+w33Asn4BSN8gzGptl5A/JluoUUw7qxgFXJKbQYeOuaYDnr8MH2BvZruxVPVVD
         23LEDv/JtsSUXgWXbUgncbr6v7wb9otJqw2ZuwXh6+JEw5ZBczN2fapvzN+VYpuo2Av8
         Je4LZfBBBv4/9zEpwScCgPlcnCp5CnojpeEtAmq/VLSNuEbnzExUyblaSPtD8zNwrfki
         b08g==
X-Gm-Message-State: AOAM5326JIHp9CIy1LbjS3EpB7Kn3pJvH9GR7+DOEyVI3cReQq9WyDPD
	9qOsUoIyl5Xp6nUZpzTiasc=
X-Google-Smtp-Source: ABdhPJzo0+Nr1GaxY+ta+cSS4aODU1IC6zVTYS8TRJp1LBCXAif7V7ipNAnColmC+Qg2jP7zjAjerg==
X-Received: by 2002:a17:907:9485:b0:6da:aa54:a88 with SMTP id dm5-20020a170907948500b006daaa540a88mr22239698ejc.427.1650991463999;
        Tue, 26 Apr 2022 09:44:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:430e:b0:425:f7f0:fb74 with SMTP id
 m14-20020a056402430e00b00425f7f0fb74ls1367336edc.0.gmail; Tue, 26 Apr 2022
 09:44:23 -0700 (PDT)
X-Received: by 2002:aa7:cb96:0:b0:413:8d05:ebc with SMTP id r22-20020aa7cb96000000b004138d050ebcmr25752853edt.81.1650991462983;
        Tue, 26 Apr 2022 09:44:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991462; cv=none;
        d=google.com; s=arc-20160816;
        b=G6ZAFbMoU9R0AU6YSqJOj55zNyPh8yQXsN/+GXHI1QHt2NusRck1GckY+W9g0BtP3N
         ip1uFNDqJG/SX7Qv4Jjz1PTJW/spJ5+BErqSwrm4Y8c2n8gOvvhqhLq/y/3ZbunQiXLF
         rpPQYTDSrsrvC1gen4E/SfvSP0ggXdn/3EDfJqIlSET3jj9yRQ30SjDmGY5o7pltcNMw
         jhu6CrqfA1y2Ia1yMXsF/5aknEiBOP84eE6VOkziSln+jnE0HGyUdps/IH4ZYWTrBku8
         Z7Sd4WKrsxPXdSrRFQb66MLQBDiO92YAObSLaLQX9oMIgyC5KptK5gQ0GuxU9Ba6PTcZ
         D/Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=A3NTwB+RJ9VPcHTGR65MbBZ7w/cFn7M1ATQGzKSwE+o=;
        b=0CCTKd3jjmft4dtcLO4uHe50/UBIfWkRbJaGMQAeKorlvfg8V2X1z0M1tUHCtKAy7J
         MykKeKLMkDNuwfQ0Oh45lONDTEgIumsY2N3vtxvrZlF2+zuiEtXfkaoEXuusjxQtib8O
         ac0/OXw+8Ul/J98l39jY/Y2t2DH73uudxKKlLxpKfBUWT0OhEYAhYJzwRtcjYa3QIXWX
         qwYorBG1NKEiZl0rxlKRtCnPHScLOv9mT05q4Y5VQMcCjawiGW+OrSsgM6xd6bPFJOyv
         f8XghtoQ+sDyoAfH4i+1S2HtMoHH1NiR11guaf31cm4xRnpdvOUcN0uR5xpkCE3MO9GZ
         wdKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ev6F5DoT;
       spf=pass (google.com: domain of 3zifoygykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZiFoYgYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id j1-20020a50d001000000b0041b5ea4060asi880328edf.5.2022.04.26.09.44.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zifoygykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id b24-20020a50e798000000b0041631767675so10627351edn.23
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a50:fe1a:0:b0:425:e276:5adf with SMTP id
 f26-20020a50fe1a000000b00425e2765adfmr13327701edt.284.1650991462573; Tue, 26
 Apr 2022 09:44:22 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:30 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-2-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 01/46] x86: add missing include to sparsemem.h
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ev6F5DoT;       spf=pass
 (google.com: domain of 3zifoygykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ZiFoYgYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
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

sparsemem.h:34:32: error: unknown type name 'phys_addr_t'
extern int phys_to_target_node(phys_addr_t start);
                               ^
sparsemem.h:36:39: error: unknown type name 'u64'
extern int memory_add_physaddr_to_nid(u64 start);
                                      ^
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-2-glider%40google.com.
