Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ7A6CFAMGQEYICUW5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B74B142242D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:19 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id w8-20020a50c448000000b003dae8d38037sf7188307edf.8
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431619; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZhwD/MKOKwu05R8/MXfyssi4Vl2QWuJGC0tSKFRqfzTUdhKEsyaZDT1kYfP4DVe02
         vXskZzKd5DU2ISt8ADLw67vKJeKK6Dm0eM98/gX45wyP84YlL5zH3REaDvyw8EJuARAQ
         iBAfc4EooumOCsMYUOZY+lk6Ts0I4jjB6bhpvBCW6cbVh9uR4auEMIa0aPSLsw0a4Jz4
         VP8fl9MWn8eJhZYIy7QVqpqEzN6h9PKdOz0rxsyzxt+uNIJl1Yrs3wk2T9ei+F3UOcbu
         H9P7A23sxNUhJ0iK5HHg5TFVIyWz3z45Sg5O2bJ9mEQa7rlCMwMUsoWinJialW4uOaGv
         yhCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=WIwFBws98ugiDVmf4Nghg+B7ao1ij6D+edpY3aHrAgQ=;
        b=W6TzI/CurKTGZ/kCp6VHPywI+IvkKcaOvNZrsm779x5+Jbb4I97FJvgNyU/jbScl+G
         RrsDiLcWkjWrISAgCArVc5ERfxKGg50OZGt3DmCZIkGPV49TG2veKU6bFLyz6ai4mO7R
         GvyYBMuqp/qHOSL11NQYLg1M+mz+E7FDavpsy0rjhM3JzYj8Q7z/w0hijvzdaoBm7rNY
         Ljf4o7+s6M2EfLO1V3IwlSxZif7/czx8hLDNJrZytRis4FQBsUpzPPlPuolEBkdfZzgt
         geGCfqvXmAeIfImwyLluAaPs4UDSX91Q33wtEPTBUoDxg5r/JyPKMbIeV7SITOWmpnux
         Li5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ets2sLEU;
       spf=pass (google.com: domain of 3qjbcyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QjBcYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIwFBws98ugiDVmf4Nghg+B7ao1ij6D+edpY3aHrAgQ=;
        b=ONbAC4RnZiCxCG5NZbHSN7wPJvcnyfRZOQ88k873c98HFPFlb4Q1eKmOjomyoRcYBa
         VjqdCJ/uF/8nXXkBySP84tt0wxaXRBr9bnAVBB5OxpJyMp44xuwwH1xva7Ojr+iCdmEW
         9BoiV24hcVCOHkU8HvnczQGFA6mSb4y/wzT9CFLL4TzEnZHDJkb/vjiTU4IItypbPRA/
         3/yCwHebasws17/A6zLjOhJjbdCc5flePVxN27iH/ns/ihXDL2c3AOXGcTkAj5FcBhmh
         DK5qJ/wPMMRjIEIa38DGT20AZUSCdQmY1QU5xFk3xjo+mHiylmKQVP0GCiO60iafGIjt
         1xag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIwFBws98ugiDVmf4Nghg+B7ao1ij6D+edpY3aHrAgQ=;
        b=1ubZs7rrnvspg0DF6g1LJhI9bTaFgpZIAmXfq+o17x5mIjZxoe2nBUgbpeM6HcxfO2
         A2lM3VY4Rabd3/Ge/WkcA3hDq//sRydW2i1IM2POSbhH6KvfSVcWO+5nHNTKK3TX8qp3
         sEPJxKxtZdItdiMuZCTr43j4urRcLtMuQg48SG9F8Doy2ETyHQBp0GGXkrVXwXP0LvRx
         IoootIQJgrRQZhebhEs4o77Q0k57BwNwFUxk/7r4Wr+DcSFmchM7kFmVDIOG/M6Jwmy6
         fEdK+bEhoGH3S7vHZjWuCZ4JzU0y440xh91tqrItnZGWvj+eVvtIQdBjA9XUizEVVUj5
         IMfA==
X-Gm-Message-State: AOAM530uIJudWyHQ/PtyKxex3nlcUsMOBC03C3LxNB5KYUpS9taHhe4+
	fmWOeW1a7PcKJ8lqxnwbPR4=
X-Google-Smtp-Source: ABdhPJxMYMiWaYnGl/QgimHPg91Qo45Mn8jZ7qXUcUVba+2aOpfWHUCCSSTE0sTwqVGiXxhJnX5tAw==
X-Received: by 2002:a50:9d8e:: with SMTP id w14mr24847168ede.74.1633431619513;
        Tue, 05 Oct 2021 04:00:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c258:: with SMTP id bl24ls9906732ejb.6.gmail; Tue,
 05 Oct 2021 04:00:18 -0700 (PDT)
X-Received: by 2002:a17:906:2f94:: with SMTP id w20mr25123066eji.14.1633431618445;
        Tue, 05 Oct 2021 04:00:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431618; cv=none;
        d=google.com; s=arc-20160816;
        b=jRhO5f4TCxvFS4NBCpdqNKvSUXV9NE6eETuFxerXxfzob54Jk5EgOfQpIP3f+CipaU
         sMocJC6WxsT8UV1kYmKixTb3S20IkPC+ULtEoCwu2on18xS5G3Op1XWvx+Hf1Nmy/Uuf
         5UV/x4jJ+Uf9bij247qCNtv0QnppcaPtEe2gLhut7CdT5yNddvZeDH0LtlxBTtptPMOf
         LQewBl78zLpdpg6xDohvERZ51KD9HHtyyKcyOePI8cI2Z3QtHE36d4iFzDEDp6Swwp9P
         Tj4knYyaB/kqOGJiQl3wA3DAM4nYOFL6AVhpZfCysZnWllaLfRWmCaeTB20Ms/mjjOGJ
         yUqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bAriFda77KQSvkeLAdzIsmSKLo4uFZFQooRrd/rm25s=;
        b=IxBsVB4d7sqvAowZKEdSDU8RrUTRdDSTvHwq7Pmup2DlvSf569TWpWmXcepHE+0bGI
         Nfkqwe2X0mEVC7g76Iigtrnug+ja7tNYRp05QopFXSme/uGYKrndDO5Jb9z34ZOLc7gX
         ONJ8xv3bjOplLkKmEhL+w9Flhl1IaRlBEx8Z1tMXMaAlpIqFthgZF20dO9obgxXPazNH
         ox079u1brTYSjBVMREi+70lLFzO7FCKvcGE6zPM+RX+1xHwQHoRrkdIVt2ejTIqTQz5V
         X/uK32ZH6zSOtENxpSWwjS2RaN1f0h5hjAhepeCLeFi0dmdb937Jadx+77xrNm6eLF9H
         o9Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ets2sLEU;
       spf=pass (google.com: domain of 3qjbcyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QjBcYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id s19si195608edi.1.2021.10.05.04.00.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qjbcyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z194-20020a1c7ecb000000b0030b7ccea080so1136126wmc.8
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:18 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a5d:6084:: with SMTP id w4mr17452146wrt.176.1633431618057;
 Tue, 05 Oct 2021 04:00:18 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:57 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-16-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 15/23] locking/barriers, kcsan: Support generic instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ets2sLEU;       spf=pass
 (google.com: domain of 3qjbcyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QjBcYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Thus far only smp_*() barriers had been defined by asm-generic/barrier.h
based on __smp_*() barriers, because the !SMP case is usually generic.

With the introduction of instrumentation, it also makes sense to have
asm-generic/barrier.h assist in the definition of instrumented versions
of mb(), rmb(), wmb(), dma_rmb(), and dma_wmb().

Because there is no requirement to distinguish the !SMP case, the
definition can be simpler: we can avoid also providing fallbacks for the
__ prefixed cases, and only check if `defined(__<barrier>)`, to finally
define the KCSAN-instrumented versions.

This also allows for the compiler to complain if an architecture
accidentally defines both the normal and __ prefixed variant.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 25 +++++++++++++++++++++++++
 1 file changed, 25 insertions(+)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 27a9c9edfef6..02c4339c8eeb 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -21,6 +21,31 @@
 #define nop()	asm volatile ("nop")
 #endif
 
+/*
+ * Architectures that want generic instrumentation can define __ prefixed
+ * variants of all barriers.
+ */
+
+#ifdef __mb
+#define mb()	do { kcsan_mb(); __mb(); } while (0)
+#endif
+
+#ifdef __rmb
+#define rmb()	do { kcsan_rmb(); __rmb(); } while (0)
+#endif
+
+#ifdef __wmb
+#define wmb()	do { kcsan_wmb(); __wmb(); } while (0)
+#endif
+
+#ifdef __dma_rmb
+#define dma_rmb()	do { kcsan_rmb(); __dma_rmb(); } while (0)
+#endif
+
+#ifdef __dma_wmb
+#define dma_wmb()	do { kcsan_wmb(); __dma_wmb(); } while (0)
+#endif
+
 /*
  * Force strict CPU ordering. And yes, this is required on UP too when we're
  * talking to devices.
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-16-elver%40google.com.
