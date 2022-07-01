Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWEG7SKQMGQEZSK2SDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 93946563505
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:23:21 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id r28-20020ac25c1c000000b004809e9d21e5sf1176798lfp.18
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:23:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685401; cv=pass;
        d=google.com; s=arc-20160816;
        b=JOEIyn5L1flpaD+O9kNxWgAaGceRrEc9FErhJYfPEk+lX11QjQMafSw0zXnPSS8MvR
         vWjVHELx1A5HbTVDwK0r/SPoF3liHDhHtGFkaQb+/d6B12Ilk+7igxxhqNo1iCrCkgFB
         4E6VZHXSBgFesBTHCRana1oOE4FjXsFTzKKj8E3J/KMNQc7pfQ2gfQKXeU6yWpbs9GG0
         hBCkhGzmtL+0eNVp6zeY9dDVSpskOTL0uwhedEUSThbUWU7IUNPZOTOhB5ufGR+odJw4
         fJ2VhxU0muqHLJGA18ejB4L2q18H3X8lhptRX+GpxDjwSm1fF/GGdFIFJ6A2zCEy+aDP
         gFxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/awHf9l6rLQ8Bk7+jZeh2n52pRVC1Hqbw2WLzn/T3YQ=;
        b=M/DX00GVcYjFe3a2zmOm5b4C0JY4AWIZN9DVbgYVF8HRAsQUw7jSlOoHRaUh8T3dAf
         UQ6aDOi81fgUK51TrHNBnTENyudLAp/N2CyIPqHK8xqzMlm1vzpsY7fGTZVyP4zC+OvE
         MICcCGmNREMfmr//3oabRpxTD6UBUCokJSteHJaZw1CVRbN4ZTfQrJXL1RyU/Gd7y015
         cVeBqHKHxagROdEjitrvM3Hkn4QjgNpsRPG/O/jvL/OIP5wr81ayGWWWT74tY4ffCaw9
         a8tvvzobiMklQVMEaWqYbO31fVbL/vr2FVjFQmZoOHG3UYkc4LUi7XDEpQtBDGSgN7Bt
         XBtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RMeY6Ur3;
       spf=pass (google.com: domain of 3vgo_ygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VgO_YgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/awHf9l6rLQ8Bk7+jZeh2n52pRVC1Hqbw2WLzn/T3YQ=;
        b=F+yc8HoMNPBtRMaTkxCmWXGew4kp/Lw1xrqnpOfj+ROzKfXsLJLGHIbiDc30SBZ5Ke
         0G4+rQNr2cKp66nulVgCpHSIJjQnF9AILJqxU4lEdsMqsmcIyOJdzRCB4R2hCCBLDgYW
         R7EBwM1CmjLUewuw8Sv42eL6eSClU3LfEzmbX9KGbe1lpFg5eRftjazVUukMhRYr5y12
         AXw+rxQrKDesCTo89kAp1RPuFmlmAvpOxMWJyNXb+YDMWdBN+LqsQuzc4qz48xaQkthE
         J/va4X76leq4+tZc5E9zOKWji9cLEMh6ce4CmzNRBuhznXYxfmC4Uh1CReTD/fqkxzTt
         PimA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/awHf9l6rLQ8Bk7+jZeh2n52pRVC1Hqbw2WLzn/T3YQ=;
        b=NJTHWSbZAVhx18Fc6ouCasFbsC3Am0vmSOPw1281y4gB19TZleQ64phuw7JMoz67CO
         TXVF9BKNv6ndwhSKtVLYiGC7Z32J4aIYy2sxs2d4kTJsehyObjfwsaem/katnq2zWC76
         ifKOhpo6yHB1N05VfNb0CPLfL+R5ANTP8In7kmF9yuUI0AMTzv9huwfecGG3JZpIZbMg
         vZCYe+EpxF9VqNVLOw1ofv/nQc/yVwpnpKQgMh30TbdqyCsYZndMt5YJLiE9xRhcAqfr
         3YnoReVLKsR2GPDBdHZ6kY5h71dh9WbfTkwv+4x0o8lxQPVdUpw+8+Og8dbQZIvuqPvh
         /rfA==
X-Gm-Message-State: AJIora8RuVxRpoS6luusDxUHcPb8aiPR+AwAvUHoFxTl0rtdHK/GP6Hr
	iUG6b9INvaFJ+M6KJQhSE+8=
X-Google-Smtp-Source: AGRyM1uEJq17hUnszE583W8RyPxKW0rznbeEHNPdr4EZIPMnmxaLvhten5rpAeZ9/GcSZawi0bcSAw==
X-Received: by 2002:a05:651c:88f:b0:253:f747:2fd8 with SMTP id d15-20020a05651c088f00b00253f7472fd8mr8399532ljq.496.1656685401127;
        Fri, 01 Jul 2022 07:23:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5a41:0:b0:481:3963:1222 with SMTP id r1-20020ac25a41000000b0048139631222ls85552lfn.2.gmail;
 Fri, 01 Jul 2022 07:23:19 -0700 (PDT)
X-Received: by 2002:a05:6512:3d1a:b0:47f:79df:2ea8 with SMTP id d26-20020a0565123d1a00b0047f79df2ea8mr10356683lfv.610.1656685399172;
        Fri, 01 Jul 2022 07:23:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685399; cv=none;
        d=google.com; s=arc-20160816;
        b=z3tXAX6FSNW8nXaTb07vyp3gyUVPo3vhHke28cqjIH2AjLaGWQCx9iOrhjS7m/JxpZ
         kSJHJdcMprktnodN6BsstNljchiOHZ6I1kaLs7fNxYEPCAaxN5vJzfFGUoTllQhNOCTu
         fXZjvotB17hALGuAvEctSbX6mrmWvvKQh4CzEgdNPYaTO6yAywgEnHiX6MryOwhzjRBX
         0cjAY8UQxIo8AbUAYanPRNGPuBt0+/7VUQ+jKsT48bGpPdoHm+62sGzljduUISUiemTp
         Q5ziHoG5egWNzkZdcj1nI6MhL/blH61YxgPfuQGElVRYysL69U3FFpiR50Dn0RgEqV8R
         4Ocw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/yIHROt1QYP0boO+vuzmQ126QU/rx8ZuEvPrfW89F9Y=;
        b=iln4I93jv282Z8EnJRbP3Tg2MQ5O1Bs29Ngaj/qFPr4hnaVoLhLgeC7h4hiaWF4RgD
         cpCEZ166glZ6VJ1pnenuk4PbS0ToEKVvjTN54yhFo8S6Sg5J0tZ9mdRzGRT/tDumbSVB
         62LhT6M1oltYvuja5M1t5zSEVoX6+9NlkRCuJdE2K57/lUK5yXW+Hdoiu/JZZ+jY/IY4
         2kPdl3IlBBzQRyajTClBzfxRYEoW8xLI7hBrBbrqda61SKdQf+ugf6enPfgOsXL/cjQX
         jxAE69FiCNImxzMR12XxphkniqsCWIzVZbopwRFpGiSNKtERCCQmxmD+bjFJ5OE3ZwpW
         /LmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RMeY6Ur3;
       spf=pass (google.com: domain of 3vgo_ygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VgO_YgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id c38-20020a05651223a600b004811cb1ed75si648451lfv.13.2022.07.01.07.23.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:23:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vgo_ygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id d24-20020a2eb058000000b0025a7f5ccae6so501250ljl.14
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:23:19 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:1588:b0:481:1a00:4f10 with SMTP id
 bp8-20020a056512158800b004811a004f10mr9629583lfb.435.1656685398820; Fri, 01
 Jul 2022 07:23:18 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:26 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-2-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 01/45] x86: add missing include to sparsemem.h
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
 header.i=@google.com header.s=20210112 header.b=RMeY6Ur3;       spf=pass
 (google.com: domain of 3vgo_ygykcxuzebwxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3VgO_YgYKCXUZebWXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--glider.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-2-glider%40google.com.
