Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM4H7SKQMGQETAUVNHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EB41563536
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:53 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id d24-20020a2eb058000000b0025a7f5ccae6sf502491ljl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685492; cv=pass;
        d=google.com; s=arc-20160816;
        b=EZ+e/itkL1Ax3XKh/OdCIwQflLiP/DM9di8Ll3HsL+cVbUkfxuxRBjyLpqPaoMOWDt
         Q9T19KdKMHIIdFe6G1rcyiAKwPSHR66twN1xQkJQV/vTSmKRrC/0r6yGtucw59GlGhK/
         XCok80pL6qXXMZnn72kbyiYJ8vGAypBE8q3GpsbcuMQNrVHFsibaMiKchkD0q+Cwv+6P
         W+Enonv+PDdYQ56YnqMboSeexGyBoHfa9mbhqLNcCUFO8YamnEzj/pyJfH8SUKY/ViPM
         RFts/8T+BzuOUhoK/F17Fda4hYTdvXO7f0Jx+3NvjWwcyiuRfZwM5DbXVFy2ihiLjeaN
         3nwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VzPw65aYeVO43yBOCZ0ZxvwfcgdALJcnuy3bCT9nYdA=;
        b=MrnD159yJYxuXdVJKMMl5yK+AX4BWA1upo0KUr8sXAqjpahO/sTvhbVqV/0efYw/lH
         qxhDkUUcmWM6dbH3/Bci8/GDai2pSdkmyX9pJncthXhAjoosULCI2qs2+rw46SU72mcQ
         cMaN8CLFBtfcI/RE11bnT4+jTIiTEqQhEU88+knTVX3E4IeYGh0HRyymvegcTiTjR76B
         OwbS6awxzCW7+Ka/PX8hFpXNrB2p95AmpOmxkZYMzXrOo16SW1w9TJ4NHsAcanOaOAf+
         2lG9ZVWsyPu+uSrfmkA4dWfF1reGUBgdpJd4jLsyP1dQtAVF2GYv/hk2E3skwmdotPg2
         Ca5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ReTKlob9;
       spf=pass (google.com: domain of 3sgo_ygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3sgO_YgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VzPw65aYeVO43yBOCZ0ZxvwfcgdALJcnuy3bCT9nYdA=;
        b=mriifOitCDCAC049veiLSqYRc22oH3kiATpnhHPXJP9KaD1R9LpqZpWG9bZL+w6oxs
         UbwzuVuF1cQ6ufpmq3Ztfd3KDMAretiRq1lYXD4e+OgU9BIs0i3h6q167sb51U34kEDC
         uJK6Y4z2CAKjQz1dVKKtLD8pFvBh/N2BVCnmy0dclJ4WihVXucgScRD5ta2s1HvNxodw
         nfuCZe2rF3fa4ZKFX/d2+hBCIJiSE+xSuOujmbAgF1uHlJDg7iN5jZdLoCKS9zcTx34s
         1Zngj1q59K9xrX7dAwYmJ1eprCiC+hZSHZtOhY5HJEjOCpw0wkx1BUHMplDqWEHt8coK
         BUag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VzPw65aYeVO43yBOCZ0ZxvwfcgdALJcnuy3bCT9nYdA=;
        b=6hqZ4yCnutDkVSt50tYsJjLKf4JuZlvmTSatsBMyIci5Zi0cA1vvPLNuisrtkB/dkR
         z2LBqfTWJaP/de8SkObxncuY2DVQueshIEMNYp/DwLoflASACkN1Cqdn7JnFgIYIVTED
         fPQPEVCFz8E8y7laynWvhTCEwXmCe0wHMh5tnt0SbH0hoMHJblebagTfwonqJz0bQels
         uB3HmWHQdrmj2FKXgG0UsIl5LPH2ksmqonmbzK5L6OBLhWg0enQC6CN83DIPhpHli3K1
         nIVvPFbeiR+RiVGueKVDxazb2V/fBjvzJ3SK927aWr5zzYaUp3PeFYsQfJ0lkYue5Wmu
         BQqQ==
X-Gm-Message-State: AJIora8IpvN+5W0asclevmVSgOIcQdWpWzk3AsSgG6qNA+pvs8YMOmNH
	bWd4KExOBxmL00D9a/6cQt8=
X-Google-Smtp-Source: AGRyM1taE3AxZnEZLjXhc4i//LQ+VnhXiNyJjIPQgsHJvk5vxEAG4EHTwEGqjWKO6IuR1AICpjOYbw==
X-Received: by 2002:a2e:a309:0:b0:25a:70f8:f0a9 with SMTP id l9-20020a2ea309000000b0025a70f8f0a9mr8448953lje.444.1656685492711;
        Fri, 01 Jul 2022 07:24:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls88722lfb.1.gmail; Fri, 01 Jul 2022
 07:24:51 -0700 (PDT)
X-Received: by 2002:a05:6512:10d3:b0:47f:9ba7:5463 with SMTP id k19-20020a05651210d300b0047f9ba75463mr8995876lfg.657.1656685491064;
        Fri, 01 Jul 2022 07:24:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685491; cv=none;
        d=google.com; s=arc-20160816;
        b=v5NRNwiQu0ZPCaHtkVzK6CffZcWtay+CYYRgz8tHe+J40m4kR1iM6CwW/k4QcS3CCo
         BfZcmCbycsIbYgP79SCyaMMXYCS10rSo//fCXy2vASaXq1ci9HdTO+PXSTGr+NNQfgvj
         8+IGRT31s2bQeCFBMPHTFJIELrMb7t8sYR/wKzuyPvRocIvVlmMXEcEo4CAlO0Z74pak
         dgsTZyIcGoxbMFD5vsyjifDfU0eaWu2HwEQ6xMDXENzvQugwTx0NArLpc3JRmgHAyGQo
         H26b7zRog7Xf+CoHAHBqOdL4haunuhGr5PAf3ZUQgdg0Q0kaOj8gH3ZUIzKWGym3MdwX
         8BhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=J/zoX+mhuBfgzG0v9rZx6dvFzp5UyG4GyQqVH6m9IHs=;
        b=B2zoaUn9kQRoBzZxPBdgyM1VfQInO/Pf0U2BixRKiaDqu4SqKsfzyc0wE0IkFIsszv
         8+9fT6DLdF9NgeZufgvku2PLY10XOnuAcpAqee4VmX9GwNi4orG+KBQsnf9TujfElBjZ
         h+vUbrsv42NMabhjiGzOLVXIH7MZB1nKgcdkAOJausDJ7pe0UJM7TQNYWaMPnys2UjMb
         WsbQAOFol+SroqFK9ivvFlffOYGmC73F1M1bX6sEogb5J5qZDyyox4I3Do9bdEtS7bii
         he2pIgPKrPphsZWFiBJm5bgx/J/i2aetYYVxlVrlSHB5lIhHT4CXVsnKkfhIoxN9Nv1k
         k1wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ReTKlob9;
       spf=pass (google.com: domain of 3sgo_ygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3sgO_YgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id o19-20020ac24c53000000b004810d3e125csi765420lfk.11.2022.07.01.07.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sgo_ygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id nb10-20020a1709071c8a00b006e8f89863ceso838674ejc.18
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:51 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:907:a05c:b0:72a:3959:43db with SMTP id
 gz28-20020a170907a05c00b0072a395943dbmr13506354ejc.359.1656685490466; Fri, 01
 Jul 2022 07:24:50 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:59 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-35-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 34/45] x86: kmsan: skip shadow checks in __switch_to()
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
 header.i=@google.com header.s=20210112 header.b=ReTKlob9;       spf=pass
 (google.com: domain of 3sgo_ygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3sgO_YgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
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

When instrumenting functions, KMSAN obtains the per-task state (mostly
pointers to metadata for function arguments and return values) once per
function at its beginning, using the `current` pointer.

Every time the instrumented function calls another function, this state
(`struct kmsan_context_state`) is updated with shadow/origin data of the
passed and returned values.

When `current` changes in the low-level arch code, instrumented code can
not notice that, and will still refer to the old state, possibly corrupting
it or using stale data. This may result in false positive reports.

To deal with that, we need to apply __no_kmsan_checks to the functions
performing context switching - this will result in skipping all KMSAN
shadow checks and marking newly created values as initialized,
preventing all false positive reports in those functions. False negatives
are still possible, but we expect them to be rare and impersistent.

Suggested-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Link: https://linux-review.googlesource.com/id/Ib7d4d70946f08128ade207519c1ee405fd812839

---
v2:
 -- This patch was previously called "kmsan: skip shadow checks in files
    doing context switches". Per Mark Rutland's suggestion, we now only
    skip checks in low-level arch-specific code, as context switches in
    common code should be invisible to KMSAN. We also apply the checks
    to precisely the functions performing the context switch instead of
    the whole file.

v4:
 -- Replace KMSAN_ENABLE_CHECKS_process_64.o with __no_kmsan_checks

Link: https://linux-review.googlesource.com/id/I45e3ed9c5f66ee79b0409d1673d66ae419029bcb
---
 arch/x86/kernel/process_64.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/kernel/process_64.c b/arch/x86/kernel/process_64.c
index 1962008fe7437..6b3418bff3261 100644
--- a/arch/x86/kernel/process_64.c
+++ b/arch/x86/kernel/process_64.c
@@ -553,6 +553,7 @@ void compat_start_thread(struct pt_regs *regs, u32 new_ip, u32 new_sp, bool x32)
  * Kprobes not supported here. Set the probe on schedule instead.
  * Function graph tracer not supported too.
  */
+__no_kmsan_checks
 __visible __notrace_funcgraph struct task_struct *
 __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
 {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-35-glider%40google.com.
