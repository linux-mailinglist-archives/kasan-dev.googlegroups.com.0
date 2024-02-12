Return-Path: <kasan-dev+bncBC7OD3FKWUERBNVAVKXAMGQES575KSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FF56851FD6
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:40:07 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42c685d0b1dsf29121cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:40:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707774006; cv=pass;
        d=google.com; s=arc-20160816;
        b=bM48gK7rEQH+R7eff76zGyEPcAggxnMxgkBMSzCn0q2GTNZE5bQUOcI/Nu2O7YCEs0
         9iLeAD00gm8WqlRGbZTAliDwT/Z95d9hXQ1oOPDXju9vLUk7MClR9/8fP4Hd7dJMA6HI
         4BRBTb13Hvp3iIiXSjhhN5LoF+t5qKdPxeRpYmf2RXiNXXOvKdMRs6bLaLt0PBabuQnI
         GFRcGn8M6Y6obovHD8mxY4P52WAQzi9CBhxrz9ct5SZYcEUslMju6LX85Jf8lLv/X4Lr
         ZKLe130FbgOVcOgTfvruGpOmN3vJ5+XnbsBcKOAiye82Yxq5aXmIcetxb/M2ODfG82T9
         9BHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GeQ+1JfUx4UzFgW2Kc5qSo/2r4S9KFtPteQOfi2VSdg=;
        fh=2KCxTEXjOO1Q8gW+EIuf+1fSYkfOKOAzHlsvcCeB3Kw=;
        b=dd/sCYZlp7nHSXEovMsbDcgEHfBj+i2wvkPjwBPOamH6hK2dy64isQdTj1yJrFL4ht
         eGLzuU7cZQKJtbve2jQgoKB9yA7yqm6nCvAA34Ygbql6BmQlPdARD8y/5k0oQSJujS8c
         E7+fGCUQwqw6rR1eS+lENbFc4o+O5R0FP1QBM81WNvQ5z3jxw/rW5G+69v22JB+7n3je
         tCO83EghyszC7NAtPUEam5bazrpT2OfUMqnwOhTKF5tI0aEaSkozGsCSeMB/ILSi1xjO
         6rLDPynUVX/7noG38mjMKVA5kfvVrY2xW6xB4JR6r+z71DBSF5qSkNr+QkQhazZV2cFC
         E9KA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RnCSnN1K;
       spf=pass (google.com: domain of 3nzdkzqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NZDKZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707774006; x=1708378806; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GeQ+1JfUx4UzFgW2Kc5qSo/2r4S9KFtPteQOfi2VSdg=;
        b=FF0j2Vt/iKO58vNspTetUnt4X5MFLjXVVa5Z3A38zQKZ78EhlkRRL846YZ+10JIAe8
         OaoWNJ2DPEZVc1tMCUtJ7oFPyb1oe6TOgO9TXqGd5J5D9fEmemYgVRqpa+UsoPtbuqD1
         kbXTq5HtFkJ2FszT3GLxuQmBI2hF2vRWfCR5tyVHkK4QlBxPV3Zx0KTBl7OM+nUWLUEw
         PAR2qNWgdX5veSiPTh57D2LEzH29KPdfJIQZAbaXgNdRGlUsMLA4L6Avm6y6bLvZlyKb
         c18U/LtUpJ+l05NB0NMmx8eF3nPISabkKXy5IIT1WdeDDX/xEuOfwcMaiHXTwz5Mxn1n
         eLMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707774006; x=1708378806;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GeQ+1JfUx4UzFgW2Kc5qSo/2r4S9KFtPteQOfi2VSdg=;
        b=u0AoelBas4+Fiuteg2hZG3V8qT5N1Ho/8TGd6s1QPJfV964oAq9uu4zW2tmvX2K7tF
         98HJ+wcGQNeUVYlgN7rBYHk2qN8JSMic4BouVwMlsIF7r6SALirguK21LVrcYsPX8JqT
         S/beRz26mSeIJ5/gjBpz7fCft7bVHJ+ynl160cDZ09rYw+1xXsQbUwQGtpWqgd16G7KS
         0qjSQOraSN/7gmQqmLNdX7OvKgRMSzUG06Uu5wJ2OaL8MrTT5Z8c0PG/r6dzsncx4HH1
         yeDOG2CcKWdFFXYGFSdpZugjWtYQKxqRYIuVw0uThsDQVxhuI0TjmhswBnadKNPIERuk
         3uYQ==
X-Gm-Message-State: AOJu0Yxjyg8jK0GMmk6L19urwG++vd404AMEbBSoy8S21KnAHomP6KJh
	VlEhQ5NoxkB8E4ke1IO7uyD0zqhF2YmTaQjcMoXJT7C45Noh+Gtw
X-Google-Smtp-Source: AGHT+IG2f0GZuS8bxqTdmLQTT2QT4tYRyVbrQcczBM5B3xFbCvhSmD0/z6WQgmeoe3ABSc6aYw/pJA==
X-Received: by 2002:a05:622a:30f:b0:42c:443a:3fe2 with SMTP id q15-20020a05622a030f00b0042c443a3fe2mr25884qtw.26.1707774006532;
        Mon, 12 Feb 2024 13:40:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d29:b0:68c:d864:e37c with SMTP id
 f9-20020a0562141d2900b0068cd864e37cls4549774qvd.0.-pod-prod-02-us; Mon, 12
 Feb 2024 13:40:06 -0800 (PST)
X-Received: by 2002:a1f:dd83:0:b0:4c0:305b:694e with SMTP id u125-20020a1fdd83000000b004c0305b694emr4598469vkg.13.1707774005886;
        Mon, 12 Feb 2024 13:40:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707774005; cv=none;
        d=google.com; s=arc-20160816;
        b=nXlJYvFlXpElrbbtMtVMEbP2CJB+tw3X2zMNuWUpcyLuTZPgJjdK6zpVPnE8D54sHB
         8cLWqCfgKB7zE7Zsy1rguKdK9diR9PaxqEl+DmpnwBDsDXxRev3afDElwW44tenW+Tmw
         ULG/k+oHev2AhC87l2rW50wzJ039RouOCPX+0yhgptw54slaUcIEZ8gUp+2ZWw6gHAgM
         h7nk07iaMVdkAYwjZNLJIcN/7wsv+NxQGteQIWzpQfyHHhIWZzy4ML0FdMzSCke4c+gJ
         d9OHsttrVJ6F4u+VCtyIoe56RihDyKsoaNvrP3x5EQFK2caP7HIRMU4DVhAX3zzj9q0N
         wc0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=8hiMFMYdTb9wRLf05RpnPyNZaK7+4nxliVbJC61s+/Q=;
        fh=2KCxTEXjOO1Q8gW+EIuf+1fSYkfOKOAzHlsvcCeB3Kw=;
        b=Hk3lEenpPERkkAHYiSiiKhFh2Tni1d55P6jO5N+9eL8r4kiIgBFB2FKpmLzxeFZSDL
         xJ0sFKvovr8ASPH7lxHvaOnK3gVAUsAAcQNHqo0P8p5aaU97A9mnxUhYGCxZQBdHiDRn
         DHG/S1Y3hn8d/hT2vQstRNHKZAoukXlqbwGXkUxq+wOC2rPHsAuRij4o3dElJJpR422l
         TvMHWgZA3t5cN60/2dUglq+4MZJq97P5uLzN+p0u/6tAcbRZgOPHFEhsN5E1xxlWq2UY
         h7Mp01eH/h323rbMrX4PB2WbZSnYp4pHMJuwxy+LCCH+ivcYRO0k+4CdCTgplT792J3z
         D67w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RnCSnN1K;
       spf=pass (google.com: domain of 3nzdkzqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NZDKZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXKu3RXC4Iob4BPFpL1e+sFWD0oLYv9X5cib2VaJsG0r4XX+MNe+9aY/w+I+8/AhUk9wsYNZK+Xj4oAvnL00DWVV1HGh10jDpQ1/Q==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id w27-20020a05612205bb00b004c06c3ffcd9si731688vko.4.2024.02.12.13.40.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:40:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nzdkzqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-5ecfd153ccfso73581867b3.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:40:05 -0800 (PST)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a0d:d650:0:b0:604:7b03:4223 with SMTP id
 y77-20020a0dd650000000b006047b034223mr2206277ywd.2.1707774005345; Mon, 12 Feb
 2024 13:40:05 -0800 (PST)
Date: Mon, 12 Feb 2024 13:39:01 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-16-surenb@google.com>
Subject: [PATCH v3 15/35] mm: percpu: increase PERCPU_MODULE_RESERVE to
 accommodate allocation tags
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RnCSnN1K;       spf=pass
 (google.com: domain of 3nzdkzqykcbqmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3NZDKZQYKCbQmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

As each allocation tag generates a per-cpu variable, more space is required
to store them. Increase PERCPU_MODULE_RESERVE to provide enough area. A
better long-term solution would be to allocate this memory dynamically.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Tejun Heo <tj@kernel.org>
---
 include/linux/percpu.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 8c677f185901..62b5eb45bd89 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -14,7 +14,11 @@
 
 /* enough to cover all DEFINE_PER_CPUs in modules */
 #ifdef CONFIG_MODULES
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+#define PERCPU_MODULE_RESERVE		(8 << 12)
+#else
 #define PERCPU_MODULE_RESERVE		(8 << 10)
+#endif
 #else
 #define PERCPU_MODULE_RESERVE		0
 #endif
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-16-surenb%40google.com.
