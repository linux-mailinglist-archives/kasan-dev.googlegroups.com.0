Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQUH7SKQMGQEEMH6XQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A234F563540
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:06 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id h18-20020a056512055200b004810d1b257asf1183747lfl.13
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685506; cv=pass;
        d=google.com; s=arc-20160816;
        b=RLdceM5LS3PTjlkFgu4e0ey6EEmNVYdZQTZA/R6fwnhlO71qO55A8iSkdj/0/kYExj
         rQe+dq3MpFIs/P2AHZbF/58JC+Uc8L1rGKOkIWNkUWJRt4HHQTFwib1FfD01U7Rk6u2Z
         H/9F2hnwKZVf4S5a9GK7ybvFK9ebR6qPm5XN1E5FilWbVXRYZiC81+N7wDh8SbWsfaZV
         CBiYE7bS6qS1INS44jv1QYLFeVHiKmhqKb9kKzW4yGhJ6H9RbZTil2q0DtN8E4V3jbn6
         icIPwZltoRxJeadoex6dzXMROtuTSkdqGAMF5iOErU3kTCUx7jONi4AMJB9zviUtA8pc
         VefA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oVfxXfE7tWPFeJbeqtjM/+xjk5EqQx8X/po46WZoMgc=;
        b=XzUWcDPifNxjVDwUJDBHxwLMMtWBiqCNSROurLX0BjbpDyMiu0dMBpqbLc76oYxi9R
         9QJxyt3ETwNm3nSZ1VBup8xYBxr1yyW9J6H1zE0w5TPNt5OGVdrjbb1c42qxj68Ow4LP
         C/J57bk2QUbLrBYq+U6shAThCRLNFrjqlfk6XZrz+33wpvK2fFFLkTTv18cbdx7BroL4
         3P0W+a6EmP42nEbB9yqp8cPRGz2gEa+OjsjsFvLT0yupuj9kK+Luq+weNOc+zvRtyuER
         aza12Qy6GoDEOyI/Jt0tLPEM+fns+n/H0pGOZoecda5Bc7SHEBkoEAiF1upG+LB8fnTX
         Cjlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anOUkKWt;
       spf=pass (google.com: domain of 3wao_ygykcd8hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3wAO_YgYKCd8HMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oVfxXfE7tWPFeJbeqtjM/+xjk5EqQx8X/po46WZoMgc=;
        b=ER95iulPamdbbQ9JfTHuA/5eB5KbPQrfrPHolY6BlVd8fzrSFdXprpvdCcErBp822Q
         FyyXp0KRUhHvfZNGpxCzujZim/y6Uwc+uovxdQFL8DN+3o13GJq1qBOna9No/J//YV0R
         JTP/WH0cyFFZwJH07rrVJ6kWN8/wOQVpTX/ZQPMp3aRYFh4FH9le3wsIA3yymBrQBZsf
         JOyibPOHmN0xMPkFQgpqs74oIaendeOdkgwaFfwmaEtwXovpSJ/0QzWOnproIcV4shPg
         WkQJuiG0iFK6Hr7iACmR9MFx5MpeND+0Veh6F84UAZGC59wCZyKbgHBe+rQgdBsxWXO0
         rQ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oVfxXfE7tWPFeJbeqtjM/+xjk5EqQx8X/po46WZoMgc=;
        b=Rbov48bhETZvKvLE7BrN7ySzm+7/3P/P38EdInD2w1+0jio93hbIr2aQLFky0vUPCY
         ZbliJG8cVo1iWf00wpiMwRvIIBCj5dScLuptdtydYJgq2e5J7bnqnePsktB/CbXH8Dna
         dlqK5rQtfgfRRAaFX1awqmLNZsFyHZkI/hObfBNrQ4yyQzx4TkTt+AM9MkFpk8WiRM5+
         D0oOP+W2y3qPlh31MCGxpwpgKMcLwj+HCzN7Li403LC3QtBUgYmdKUnP37fV8pFijxuf
         hIDKsSoCYI7zUPVTNPAhp+XUleNb7EQqqgEAFw2vZ5xRwUD/UwcaAXbFn4254ZnCa0fI
         s3uw==
X-Gm-Message-State: AJIora/H9eTL/55vHGOicXstmEOcdmuThKV8xm/WTy1lL1BsowQ54il0
	HhFlJ0JpnlvSpPsAs3fMkbA=
X-Google-Smtp-Source: AGRyM1tW28oBxh50NxtgcPtZ/3x7uxTrZOM9ntuOE29vU/rCq3qF07McSlBxlvjd4gzc19YZ1VY8lQ==
X-Received: by 2002:a05:6512:39cc:b0:481:1b6b:4a7c with SMTP id k12-20020a05651239cc00b004811b6b4a7cmr10196044lfu.597.1656685506462;
        Fri, 01 Jul 2022 07:25:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238e:b0:481:2fa:2826 with SMTP id
 c14-20020a056512238e00b0048102fa2826ls89095lfv.0.gmail; Fri, 01 Jul 2022
 07:25:05 -0700 (PDT)
X-Received: by 2002:a05:6512:683:b0:481:6f0:8853 with SMTP id t3-20020a056512068300b0048106f08853mr9080528lfe.365.1656685505372;
        Fri, 01 Jul 2022 07:25:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685505; cv=none;
        d=google.com; s=arc-20160816;
        b=RIe+qbRIuoK9dDiEcBQl4I8c3ZIM1AbmpNd132JtJwwKUXUE/IiBKj9B+Q5IVx/wVg
         jfjEIe8lcS+bv9ZNrsy6UGyI1SRjc93boQGBLOjjQ5tVichmTeGz+lSjX29zCLGBGOed
         bFY8ubrcGEFmE2YPoYIFZpZiiKIYgOqFYZeEOolbuVtBFs078GSc6vVGZ7eUBoRG+Jo5
         BK5lDt2Jbjx6/VAWy9mYobkMXqOhMEhi13Q/uqteaHjnRsbkRYN5ncsXhv86oHdU1dRp
         HQJOWw2p9vbMLSh6pvOCgS1p/Qx87QVoRjlyMoU2Yx904XEhYB7wunPb2TySASa4WJyM
         XB8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=MLo3LhenoRrRqNTI2r4mtWD3J0vGsm9bvjleadBpMkY=;
        b=wceJKJVKpD2nOFKJgT/kMEftszc5+14JPQYpsP3cW2Bm26a6NaExJv6kkOfIbttb/k
         nsvhrW+47anzk9/+MlucdCjC4EwYkpHCN5xcJ6vaoOR0DsrcgXVq4RVhVAcL82KQiaRs
         PhUdF5eYMlSL1/E/rz+pR9BGc3xSSgdeijZ9fpnvbXrfvVbU4s4RmEba0/bGMpeEyFgj
         HQckG/zavHDaX91cmc2EIkaganO2vCD0lgaIAf4t6JH3WftBO8VQLFygrNA25Q30Pg4A
         wQA0qhuIJo2Bi7qdRh2tmVb3LFgWANG4IgiUq4qiXHrmfHYDi9dRFw570GLjnYbD/5Aa
         F+eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=anOUkKWt;
       spf=pass (google.com: domain of 3wao_ygykcd8hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3wAO_YgYKCd8HMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x24a.google.com (mail-lj1-x24a.google.com. [2a00:1450:4864:20::24a])
        by gmr-mx.google.com with ESMTPS id p16-20020a2eb7d0000000b0025a71229262si836513ljo.3.2022.07.01.07.25.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3wao_ygykcd8hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::24a as permitted sender) client-ip=2a00:1450:4864:20::24a;
Received: by mail-lj1-x24a.google.com with SMTP id p7-20020a2e9a87000000b0025a99d8c2dcso502392lji.18
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:05 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:e83:b0:47f:635c:3369 with SMTP id
 bi3-20020a0565120e8300b0047f635c3369mr8918326lfb.659.1656685504982; Fri, 01
 Jul 2022 07:25:04 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:04 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-40-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 39/45] x86: fs: kmsan: disable CONFIG_DCACHE_WORD_ACCESS
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
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=anOUkKWt;       spf=pass
 (google.com: domain of 3wao_ygykcd8hmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::24a as permitted sender) smtp.mailfrom=3wAO_YgYKCd8HMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
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

dentry_string_cmp() calls read_word_at_a_time(), which might read
uninitialized bytes to optimize string comparisons.
Disabling CONFIG_DCACHE_WORD_ACCESS should prohibit this optimization,
as well as (probably) similar ones.

Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I4c0073224ac2897cafb8c037362c49dda9cfa133
---
 arch/x86/Kconfig | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 4a5d0a0f54dea..aadbb16a59f01 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -129,7 +129,9 @@ config X86
 	select CLKEVT_I8253
 	select CLOCKSOURCE_VALIDATE_LAST_CYCLE
 	select CLOCKSOURCE_WATCHDOG
-	select DCACHE_WORD_ACCESS
+	# Word-size accesses may read uninitialized data past the trailing \0
+	# in strings and cause false KMSAN reports.
+	select DCACHE_WORD_ACCESS		if !KMSAN
 	select DYNAMIC_SIGFRAME
 	select EDAC_ATOMIC_SCRUB
 	select EDAC_SUPPORT
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-40-glider%40google.com.
