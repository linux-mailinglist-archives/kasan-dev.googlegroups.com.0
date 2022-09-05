Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6W26MAMGQE7NZBISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 780885AD28D
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:55 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id b17-20020adfc751000000b00228732b437asf572275wrh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380815; cv=pass;
        d=google.com; s=arc-20160816;
        b=d9dReDYf9mOnEBIZLB9KB0yeOINSczraT2Q3rrUdaHyzfH7RDowAW96QoEedPGr2ms
         NvoxcyUPsSeovEHrIaE4oIEWjC0ZF2yDQsKzd2kd/F+ww25VFO6aiyS4zBi4nkBs0cEO
         RbG7HvAR2s3RrZ9iqRemGYWKHyJ1qROPaPPIuMePwArh+0eQ1Uvb+BxdMtzc/UTeuFsI
         xoTNpegKutd84vzKx/xSTd3nluyoCyITlYYIBcJccGYNJYuf/QHSp/swQ73mNDa7XPd2
         PeNtFRPdJ5s+lBDv/Y2kUyM8qKuQ1BjDt5B28iczS7mQjqmKFmOO8uyHhv4mMpbPZQtk
         IvUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fxQpEALI3u+bcojgD55elgWisAA3eg5KZPYs0DnjS8M=;
        b=d5mzSkISwyj6o0ydsTbzVG/KAa6/m9ruIRi69XQZEnCYOsXiNPLxjjc2Xw11l5tBAE
         gm37rveZj2r0mEZsv03eJ5Nc5ZXPD0UYacJBSEuYxRGZlSga2EovjslklM2B4qNQFK2D
         nm8IMHPX3i+kdXNcBJ+T4QaM/qeKY8aJO6jQmDKJTF4CO534loyoD6zvUN6mcVhW45sa
         gV7ynuS3yuSsIUuHD0bF99J13C92WvPmFLELVkOB8fHkyhyNqR6Nz4x2e51SNw2IGS1/
         B4TL29EQAF+rGQDlle6gAC1vmfrGFbmrhiGh8Ln7alXBvXXY6ys6Z2uJwdhi8SG9jglA
         wx3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UDsvJYgt;
       spf=pass (google.com: domain of 3desvywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DesVYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=fxQpEALI3u+bcojgD55elgWisAA3eg5KZPYs0DnjS8M=;
        b=bgpWLkEwQkseCXKDbtp2thvOG76kjYzFSFgcLiy0uyi47KAffs+1AH5RSD0Oa+m7bs
         Qp+GEBeF2h5/416o+uqOfYNb/+2XfkGwj7ccCUWGzEneVmZzas+92A8+tAZfn1Rm9CU1
         uPwfxdTe8NeN7TtNcZoqL9i9lGybpLx6OuzEn7dg1kvjDtn1nlXH37ETQlQwtHYj0W2X
         4VfKVGz/c3lYrzost8rCRFKc0VdoYaW+RLj/GioKNwGMmNPCAJOymjABHmG3n5oEVPu9
         cWwbf0m+KRLLdhwF+5PXvOKrrpBoTFdbKOLFsDPfmS2pAcNtO6XrmHIamoLpiog8ha4c
         bt5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=fxQpEALI3u+bcojgD55elgWisAA3eg5KZPYs0DnjS8M=;
        b=0mj3IegDS0aimrmI3MaiySo38NIEDaX84nySeylN+SJ/BnhLq2TKKAAYcEiRDW/lzP
         n9KZBC3Ic4ZkE7JmfhPg15/NuZuy6WT3VbE/MS9NVuS2C+6VoNyNNmx9lIYFftyRijkN
         oWG6rJw23S/nvTPsjdsc96DNO0dHPdd/UBdEP5kOm/NL46p+Frf9kroX5Bu8uqCc6+LT
         XMmVd+Y5odS/pcCDhaM6eezyb+7s/gDpjO2QmPH8+qjfici+FIURp9FrLyoNBCY9H/j9
         i8F3hGIBVVgGSHk8Rxej3NuL5gip79/3pNkaUu9x1pVLmOw1wqdSOEmCAsmhQOQ34gJg
         +IVw==
X-Gm-Message-State: ACgBeo1/rg4f/TuJQygftWRZHhvGgHdJJ2aUGiYKVKUOxgURtDLwZsh1
	AHR/hQ32O9OyZTX5ZEAzF/E=
X-Google-Smtp-Source: AA6agR5vt6YPCmoxzcUtgcGlAf0mUQrQGM2xWt4utMDAw2lOWzX+1f/Ae8iKYnnBvlnWhlWEmFO4Vw==
X-Received: by 2002:a05:600c:4e94:b0:3a5:b7e5:9e64 with SMTP id f20-20020a05600c4e9400b003a5b7e59e64mr10672988wmq.26.1662380815290;
        Mon, 05 Sep 2022 05:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:721a:0:b0:3a5:4532:b3a6 with SMTP id n26-20020a1c721a000000b003a54532b3a6ls3812527wmc.3.-pod-control-gmail;
 Mon, 05 Sep 2022 05:26:54 -0700 (PDT)
X-Received: by 2002:a05:600c:190b:b0:3a5:f8a3:7abe with SMTP id j11-20020a05600c190b00b003a5f8a37abemr10705161wmq.81.1662380813998;
        Mon, 05 Sep 2022 05:26:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380813; cv=none;
        d=google.com; s=arc-20160816;
        b=BTcJqpFPL740jnB/z4ccGtDlJOucESh/aHoK2jPQIBa5MWVjwds9Kfx+FvnsHM8Hdv
         wqLOyglTzYmvJaGrHHs8BiJ3Q9mqFAXpIv6sXx3Yv2TX2VOJyXLCo4nKJoybUOJTZID+
         uFYtwY98dHB72p5FIkSa9Dmd5FHve6BGwVMsUBQ+BA1Q9J+JrVQ4CMKNLPbswjK+stO9
         EdO2/tUw1NNdPDwgqCwtBrOnv0Yt/pzvpnIJT1TTVwxuHbZnwkbtVZb3mxT0hsakn2Or
         9f2W/H0xm5RvjJaOhnMblrI8lqfyWebVXf2ATnypo71/+Ru4e8D9y4floc+MD9a25GEs
         D6Wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=63Lbiss0mCSaP/JatuEwb7Qda7JVHXONR7b7gS/f0zw=;
        b=CNSXm270tExQrFU3fEUHSKfn69SkJNjbnFQGoowBAflBnb0dqmpl9HZ3tWCK3hQK+g
         JxTTfO6/7Xdb+1MBnKTd5oanHZZBLqhAfmmWDEAx1qNG59SytUI4P6WGEzu6XdyrE1hU
         XthjOXKVyRCyDVR22C6/SI3osyop3ZKZTyPWh+mhrLk7+dCoo2HpqTmQnrfdKzVdmXe+
         4Ce0gU7y69mMxZKiQaRUYap9JJjUBMHyYtKlyKLg2TlM5+NuyUP0X0k9p1lwZRIWWqtA
         qdhlnXXLTcWYc/nHFENPBDyU/X2fqdxVgwNz23AmRPsB39AjI6KCj92CE/720BgvxOoX
         c+nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UDsvJYgt;
       spf=pass (google.com: domain of 3desvywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DesVYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si489901wmh.0.2022.09.05.05.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3desvywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id gb33-20020a170907962100b00741496e2da1so2280880ejc.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:53 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a17:907:2c41:b0:741:4906:482b with SMTP id
 hf1-20020a1709072c4100b007414906482bmr28414813ejc.239.1662380813588; Mon, 05
 Sep 2022 05:26:53 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:50 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-43-glider@google.com>
Subject: [PATCH v6 42/44] bpf: kmsan: initialize BPF registers with zeroes
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
 header.i=@google.com header.s=20210112 header.b=UDsvJYgt;       spf=pass
 (google.com: domain of 3desvywykcvo8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3DesVYwYKCVo8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
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
index 3d9eb3ae334ce..21c74fac5131c 100644
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-43-glider%40google.com.
