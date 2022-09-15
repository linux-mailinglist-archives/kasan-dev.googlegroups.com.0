Return-Path: <kasan-dev+bncBCCMH5WKTMGRB576RSMQMGQEA6YAUZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D08A5B9E34
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:32 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id i132-20020a1c3b8a000000b003b339a8556esf118162wma.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254391; cv=pass;
        d=google.com; s=arc-20160816;
        b=VHmC/gYRQ7iWyCSF9916+Nw8s5Bg0tT2N/lEewBLjb9M/yiwMWdEexmuT4177cKUNu
         217U9N7/aLFKiTv9pwTOeWrWOUm6Vri26sVnnwTCRwexMYfl8jV8z4nafGsjucEg+sZ9
         cAfz74oyx+MABmGEsRPmAM6egU7XAwYwGmtSBxgZWoD9MXqyjukMXbbaN+i0aMqNR734
         X2FQz08GVioSu9HNOwy5kE15kwdN1m2HiEytYM7Kf7aHbxnLtsge1+EGIwgKlpQN1FFF
         z8lLP0NdURtvsDlYTbbzjD3wCkBFpVwhhUBmnVLAEE/RQO4U/H4gMGh+Xt05mMCv7DyE
         D2oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=PEuqsf9aqzHell3Oy4xGM89+vqiZ48M1PHwbtK57OaM=;
        b=WLkR6Cx3qrKOvxpoLFzM0+AKzCfVMeJerwO641/Z4J82OIYLvx2OC1x1CgZL5eXriA
         fNcINk4rXxryPGdEQeUapKsGMdT4QkmEenmC//MywCbLCcc5ecg3/dmP18erX8xQIu8z
         na1VefbNDAci9qv/cyhvDNaMJ8SeaXzagUm90bPmhXMpsrewMZQxVS6kjH5ecM3RL2pk
         n0L1c+JT5kdNSzAokEmRuwHND2lkJgUPQF//KxK9zk26J3YO2OGY7lPTYZQAKrs6LMPH
         M9Ptd5o1U3PyKv7EV1IQ10RGwp6r5rV5qo8mfCwCnXzuWXrKjpQi+peAHT4YuQKE/+G3
         lf8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ldGNVPhu;
       spf=pass (google.com: domain of 3dj8jywykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dj8jYwYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=PEuqsf9aqzHell3Oy4xGM89+vqiZ48M1PHwbtK57OaM=;
        b=lUVabRYx95parHkq/e2OidonpJBAqLpnRYrfLDSS8kCBu2Syj6xrI7bMejafVTqUno
         lniKrpH32p8imB/uR1RABaw50xEm5uJDgnm72Ox6WOo5zSbHq6sMcjeVrB5CUWZdgWtj
         W3MRV4C606YFfr6ykLYcttrKtYZQVawzceCIXFv90QBXWYD0zGZz0g8WJ6vd2HuK+G+d
         SvGYZ2HQ0g9XZ0KJ+jCwStcSEUss7M+ROYL/BthYkNUAyCQrBm9TyX6l4O8MHb07BjbM
         ac2ZXipO8cXwhG4B3C3DsjoIaAWqN35xvTovRt6lN7gddMktHZxivofnfgoM5JzqAr2q
         jiDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=PEuqsf9aqzHell3Oy4xGM89+vqiZ48M1PHwbtK57OaM=;
        b=m9iANUwlJbSKhX5GQQbQ7HMOm/vliLM+XCSPgJ5an0rn5bgPbo68FC3BAIXWIX0JCG
         spN6PhPyLgHMwzjSjHl7nrlsnkhemxSj3hBZrNOmpt8Pt2EuTfyy0URocRe8b3meO6yf
         nDm0rmVNaf21zrnpEv4AxBaOJ7N3jeAGBtKOkEw/vuEDsIsoJ0hxO7dUo6eQNTLeDpBb
         7DwuWnbCWujdMh0khfbcg7tBp4xDkxElQV89zFILPaqbItetpRrr/rq+4/O3hhrx7/CD
         gSgGveWTVJ0zr934nMcwSzBhrSiMXEs2OrQAAJjGkjR8j1qoPCJ2o47WKYz6pNx8HfL4
         Shlw==
X-Gm-Message-State: ACrzQf2KokSnwL6JXlzn84mQ61pqlDDlASnHxAO4SEldhsQkWrEUwOzx
	ALYcMuYqZEMB9gnyRcY+u80=
X-Google-Smtp-Source: AMsMyM7GFPFArz27IUrWkWGh4ZgJT2OnzEG183pv011TQ6cDY1pMclH162E7nbdKVq8fE9Nk8CX9lQ==
X-Received: by 2002:a05:600c:5028:b0:3a8:4349:153c with SMTP id n40-20020a05600c502800b003a84349153cmr190299wmr.130.1663254391889;
        Thu, 15 Sep 2022 08:06:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7510:0:b0:3a6:6268:8eae with SMTP id o16-20020a1c7510000000b003a662688eaels7267388wmc.0.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:06:31 -0700 (PDT)
X-Received: by 2002:a05:600c:a09:b0:3a6:8900:c651 with SMTP id z9-20020a05600c0a0900b003a68900c651mr161437wmp.145.1663254390933;
        Thu, 15 Sep 2022 08:06:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254390; cv=none;
        d=google.com; s=arc-20160816;
        b=MFOgUhGYCSB4C80ry9O0fXyxWaAbc1agYejCF6xTF1dZmuXl2xtmrUfN4ocYK3LYpu
         k3TOZBI/3eZ+HuU+TQk4YHiyFBH40hpLvCXPEgYAxvZgQ7S2W6dwgGTrOmFzJvWd6cQ2
         0qggAT01dWN/ETTChtbVRFGCXImL7dNKIMjizYMAfGuUjpdK7fKzmLvnaVGVaIHo2h2S
         3JzgHYgMMpLg2+490o46SmuqsNx8P0X/plM5LAuMmnw/atZrT8UlTR9ZP9OtQZBUFXjl
         NhqtK4SMwCN9RW1DtWR4wDETGIGpKaKFHD8GocRui/by4VY25S++tXwHB/wswdLyUKje
         nqrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=63Lbiss0mCSaP/JatuEwb7Qda7JVHXONR7b7gS/f0zw=;
        b=TEG4Rs70rBJjUrc4zkSRb7IWsv2hq4FGzctbTvFkGlxrgVxjoYG925IAIHgxesSMVM
         lZTlolCnjhXkBJchMOww4hxOcnKz39WhbzHtRJeEKB7lweGCLudOrJVu+Q9qA5/rjxh8
         ajuHCwVjXh/mpJfdC/oW8BryMCEcLk6mfjTT7ExWTlkbq5tgiwrRpmAM0eWAvIVwO3mo
         UveZRBQHAHSS0hlIVAd7AgcsGJpVHhIsuDToI6DJV9qajFrU/kD4x0I+2B7APCz/aLIt
         HWSe92ffCUchN+ujEyEtcjoOWALZDdjs0bmwylcaNO8rNQTfZwpuq00yDrrs9mZnTCyE
         6SyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ldGNVPhu;
       spf=pass (google.com: domain of 3dj8jywykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dj8jYwYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id u1-20020adfed41000000b0021f15aa1a8esi81725wro.8.2022.09.15.08.06.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dj8jywykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w17-20020a056402269100b0045249bc17a9so6686790edd.9
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:30 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:aa7:c1c4:0:b0:44e:b39e:2a54 with SMTP id
 d4-20020aa7c1c4000000b0044eb39e2a54mr259911edp.139.1663254390559; Thu, 15 Sep
 2022 08:06:30 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:15 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-42-glider@google.com>
Subject: [PATCH v7 41/43] bpf: kmsan: initialize BPF registers with zeroes
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ldGNVPhu;       spf=pass
 (google.com: domain of 3dj8jywykcaehmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dj8jYwYKCaEHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-42-glider%40google.com.
