Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU6EUOMAMGQEI6F3F5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E29B5A2A94
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:10:12 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id p3-20020a2e8043000000b00261d42c6292sf658012ljg.22
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:10:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526612; cv=pass;
        d=google.com; s=arc-20160816;
        b=OeurtKJUCiphyjlz7YBR3FpBjZXS51+/Sv2CPoJTCzB6By9W1wl5izgOCsT3xqK3os
         RJfGHOFrP6rdc+nh20vs5wotWuRdNzUO3o0otyXiqtiNVi1EOfhIw8Mgp4YvwzjLR75t
         BVcHTVWiy7vZMp4LC21NEC+Rv7zeXQ61Q15Y48atrXrx0u0r6PP0FdcZNYpHXAXyGO89
         N1bfQfZCBzj8OOGYKu+pGY0uQRvZvwRMl6y6FKp1Nt/gTpOLH1MuKRs2GMCOg1ef3DGq
         0IRwNpaeus4/lMGmFv/TOwVNsaqkHvpxbcHzGvlUsmgXR3DQcpJqvchmrhAaNn2OuBnl
         UWZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=X0EYjsp4i88gDw6AlNAxYQIEuXRPLcRroOdLgplVxhs=;
        b=IQ3b14c8doKIDORHSvQiHQjN1IaNj30XWVbWSfh59XSZZYkL+z4YaWn71Chlh9XAx8
         BW6fwQJjk4txYIzx08k4ovaCq/V5WEmNnf70XAxSRu8heJp2cpQdEesyc1SXSfZG0lCt
         7g6tdqcvjaebh7vpkFAXHYzqnBBe+/ZEzFosAfZNePqo53hstZbS45XVgRp0C4Quch9T
         mrrEM82YndwbMNYvQXsyg1cVX/dlIcgkO8MJauNdagBu8n5A1Ny5yZ/75c/oQivOGecI
         SYKTqr5062kXM5sOLPGaLFb2EVoNE1LS1BvfqLahFHKI/OU2ENrJYT8KnirXTpBRBD+C
         6HoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="fg/g7W5S";
       spf=pass (google.com: domain of 3uuiiywykcvk7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UuIIYwYKCVk7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=X0EYjsp4i88gDw6AlNAxYQIEuXRPLcRroOdLgplVxhs=;
        b=iKFyN7PSjNU5UKmEx2/OuyaoehsRFjd0VuruAAUoY5jJvN/MQsM+oIQkGLndEYJb/L
         Fh9LZI8ihpUXxab+uXPykQYby8zcbXK3ziK7nxtM1GrvDW1QBrlJbx8IvuH6C618ZDi0
         lKqEOjoEGCeIVuaP/Xmp7W57EUYWjTlSQFLyd5FfIZFBKFgvAQR+Z1jZ3UK98vu8PbYV
         rCMJeT4XdhqfOoLrfx6oTVNFvG/0ouQEhFFBATFair/iUXVm+0XLk9+GH4GO9+uMmpXQ
         YlcKrQioZpRydG0nBK2KhuQAmFaTZq/wSEvnVYBrtBDstfZuSp37YPlW5fe20ioEy75q
         sf9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=X0EYjsp4i88gDw6AlNAxYQIEuXRPLcRroOdLgplVxhs=;
        b=EeSdbd/mAqDZMgMkcGuhmq51lrwmsn0dPkvLjLkKT8D1gyt51NNCBiC0eY/CsG6k8g
         oH226h5ZDKmhQrV9bYRV5IOkZUArC6Kn7KlNkeRGPj1Y8S1rRgNVpp7rda0ViG5S6n8r
         FN4Iszapssd9bK+Liigvk8TWC0mnpbI83mRlwg2OgiF6PI8laeoak1xz+fayJj1Fgt8j
         xBcUw3gme3Jx9qPLkEzQZ0INjbB4y0Cm/IOmFeM6OUvly/n+4PZ3hlKusxTGfQ3TzQQw
         jhD7j10zqTOeaTnEyhbnXqtys4qPnGNU9+lRTR0gfh8hFiF6m88PtgHDp0lzba0OSAGH
         VgDg==
X-Gm-Message-State: ACgBeo1ilMNVI0h6ePd9wDXdVKC0buybhGDaKkV+aFhj4FS8PEegE0av
	BJhU1teO5EaeNEPi8G9C/VM=
X-Google-Smtp-Source: AA6agR4P9yL4b0+PEMbsx+kOwujHaUf5THuLhF2557Ca5RgFpv0Zh0NUn1DMzOFCkVmcAbLvpb5B3Q==
X-Received: by 2002:a2e:3607:0:b0:261:d4d5:c769 with SMTP id d7-20020a2e3607000000b00261d4d5c769mr2709614lja.88.1661526612087;
        Fri, 26 Aug 2022 08:10:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f53:0:b0:48a:f49f:61c4 with SMTP id 19-20020ac25f53000000b0048af49f61c4ls1139980lfz.2.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:10:11 -0700 (PDT)
X-Received: by 2002:a05:6512:2289:b0:492:b54f:63fb with SMTP id f9-20020a056512228900b00492b54f63fbmr2565252lfu.506.1661526610975;
        Fri, 26 Aug 2022 08:10:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526610; cv=none;
        d=google.com; s=arc-20160816;
        b=Jpkr7DTjxji8IySNFRIwJXhOPfF/rcH2kwbBSpCUDm0uVTrO7xrfagG5yHzCfXLC33
         F4gT3ipjN9LBErguTk1/erPSBdeVQt0o66ntmtfQm46eMhEqA1txuuX+gOnzaDJEORue
         ioUci5Uhj8C5JzLu537zAsAmphcrI82XPdenqzNt5/aJTf1nZYOcb3qH+Ft+Ng+8Jk9u
         ZwQnSi7R5h/e6lIbXzjMfjMRRakv8JqNKkvORLBkW/D7wermVF96ncHLvq91UI3KdWYu
         JC4J3k9ezpfW0Me37+MZEMctr/cKbBR3x0jTpvmSdKNL3hCX2pd9KScfOLyyU9rAdekA
         X+9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rCTBedHFoD5mjPc5axfz3IhJFNkE8btw4kiDfQuZoWM=;
        b=zk5JS0sSzJKjsAgDgMrGzAO0jJuP1p0nVVstWFvDgxC1aN3hpb7k/qN8/Fp+dYIovu
         /q0x8iMwpAkCT4NeqOyaz8Zy6+R3CpXRF3vgDPAxFYtDlJEeZNu9qgBxj4/GRGuGxcaT
         ThBrZGzbyimkivLTp0332JBYd4WahfYGnzdu0uGhd8DLwsiIeiRWot7xrH0G9hevoNqx
         mZ2aoMBIflsMKe1Gwn+bMGTzZnvNHg9GxiS+it1/SY2JD7c7W/m4fCtdeL4jGvtZqTY4
         XsUwHnPA2ndjZyY9b3/xNG8OgPv84GBCphPv/FzOYbLF9k7zvM7wCZCyT/LesGh0LrcV
         IGpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="fg/g7W5S";
       spf=pass (google.com: domain of 3uuiiywykcvk7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UuIIYwYKCVk7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 2-20020a2eb942000000b0025e576d2a12si86785ljs.0.2022.08.26.08.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:10:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uuiiywykcvk7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qk37-20020a1709077fa500b00730c2d975a0so717430ejc.13
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:10:10 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a05:6402:2816:b0:434:ed38:16f3 with SMTP id
 h22-20020a056402281600b00434ed3816f3mr7084895ede.116.1661526610607; Fri, 26
 Aug 2022 08:10:10 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:08:05 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-43-glider@google.com>
Subject: [PATCH v5 42/44] bpf: kmsan: initialize BPF registers with zeroes
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
 header.i=@google.com header.s=20210112 header.b="fg/g7W5S";       spf=pass
 (google.com: domain of 3uuiiywykcvk7c945i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UuIIYwYKCVk7C945I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--glider.bounces.google.com;
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

When executing BPF programs, certain registers may get passed
uninitialized to helper functions. E.g. when performing a JMP_CALL,
registers BPF_R1-BPF_R5 are always passed to the helper, no matter how
many of them are actually used.

Passing uninitialized values as function parameters is technically
undefined behavior, so we work around it by always initializing the
registers.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I8ef9dbe94724cee5ad1e3a162f2b805345bc0586
---
 kernel/bpf/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/bpf/core.c b/kernel/bpf/core.c
index c1e10d088dbb7..547d139ab98af 100644
--- a/kernel/bpf/core.c
+++ b/kernel/bpf/core.c
@@ -2002,7 +2002,7 @@ static u64 ___bpf_prog_run(u64 *regs, const struct bpf_insn *insn)
 static unsigned int PROG_NAME(stack_size)(const void *ctx, const struct bpf_insn *insn) \
 { \
 	u64 stack[stack_size / sizeof(u64)]; \
-	u64 regs[MAX_BPF_EXT_REG]; \
+	u64 regs[MAX_BPF_EXT_REG] = {}; \
 \
 	FP = (u64) (unsigned long) &stack[ARRAY_SIZE(stack)]; \
 	ARG1 = (u64) (unsigned long) ctx; \
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-43-glider%40google.com.
