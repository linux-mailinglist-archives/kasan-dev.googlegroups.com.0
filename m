Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAGW26MAMGQE64QECUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94BAD5AD272
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:26:41 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id x10-20020a2ea98a000000b00261b06603cfsf2832251ljq.17
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:26:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380801; cv=pass;
        d=google.com; s=arc-20160816;
        b=vfAsTXy41/3joTmgl+dhBG3suTa3DWCKxRE1o0onP9M5Q6zEj4mAzUmaTQAdhFksgo
         QBzBcrCF2HcDuHtmnlkLHFScFAk9+HcVDQHVZwt9oahPbN0mqmsWFCmfa98SpSwrYr74
         bip/zDPygQ2q6V41CLSBxMZ37H4XrDVcDCGLT5y28FUto595eXUuzVqk7Yx2sLpcIsXT
         0ZZYiWVP9gkaYRbjUrt6VO9SZHpmqE9FwD424nRki3/e1XiF32lNJonOl4oHzotFREEn
         rMhJzLUDZfJUghwx2jgSZK9ENUL2L5oUziLm1f+2nUh/TvPOBYMxeKeOOJLAyLrYlGpw
         eRMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=k3TUuN5snu+nN6R5c1nRWqjmDcoxyEveelWQchWv9fE=;
        b=xCwKKFCvxkPmUDPYQ55/kueGOzmADlMpkSzdvz9hhLt04PkGeGf+kpZoP5foLq4oZI
         hHPLAWZGLoUor8hhi98gBmIhGe1SvhHYyAxnnsS1WJ35XnS7jfk7ZU1tOZEZd1h4MTas
         nzAwQ3zF0urmVGsg0y8LGQ1G1SVehc1w9paV03NtNsaphdZgAKH2pWTuMCx2ugzdB+3n
         dC/fF2HGvH0u0GB+ZBQo5SqF/ZTfPVfWoZZA0V0dYEZTfHbqBldKcitXcQMewfvxmAop
         aQD7IfiRFgsu0rOqCcJTI2+q49urLl37MQ4Y8ORROae0Yo2ImCYaOgGGwTLjgn/k2Am4
         MtUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gBW+tZSL;
       spf=pass (google.com: domain of 3_-ovywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_-oVYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=k3TUuN5snu+nN6R5c1nRWqjmDcoxyEveelWQchWv9fE=;
        b=DKZ2o+PmBlSz0o5nkeiCPQMxaNie+uu7VhR65zMqFJVHRTpoDirjFSGbopmkeTa4dA
         Bx5YLzTWpLZuhYewf/zVZ9ivEbyIifgcQ7Qs0lo8Xailko6tbHRxNOtS9G3ZuPG3TBMp
         8zhj4owZq4E7UdUFJ3gTeP3a/8x0Zke/Oexi/ls3LZetw4p6BYYXOaTaYfjNVcy/i1KG
         jyU0IDYbgMXGkzH97x/zYNyXl6Eke9sptN7ZDLelg4DEcxqdkOTkwIEcIUysW4jDWBzu
         0m3NtqSkyRf/YNCIHzojYOZPCfDWYZSlDgao47Vts28S87vqikkXYe+xs9ck1KOB45EJ
         VrIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=k3TUuN5snu+nN6R5c1nRWqjmDcoxyEveelWQchWv9fE=;
        b=jndrDnNX8AYSJWAm06p8XiWghGkb3EpCL9vOJEt4cglNQPThE0+VSBPOCjBFWIqtqg
         uvUkKQULSaQ2DARjvUk9WVe7/dAKtgrAjbxdhYMz62YIqToKwjFxcpIEQuK6UYDxtvVe
         Oc59/sL11rgo74yY5P1qGBKENxraz6DH6rYP5pYkfS0N1TaKjv9Sw+R1gaRkfQE3ujnC
         fqPAN+czqvaXC1M1BJ11IhEqCo81DhUOqX9ODobfhkujSlucAZkvarwRpvKdLHBRvm9K
         3R43pOTpGTrTse5SqT/WP+i3m+ArDmJMVXnlrHpBSx4JxQFoYvXiDXnWVLm8ojRl5RYv
         fxtw==
X-Gm-Message-State: ACgBeo1S29I++X5Zog4vktVzA2JeuSwwohuIisBdSIXmYDL8jafN+LEk
	WUiPH/Syhv8LvAJDo9hiVVA=
X-Google-Smtp-Source: AA6agR4hsrobg2LBrY+v8/t8qXi8ZMHI0g5OrZqyOg9HG31iEgwSVmUrD2ZzWPuV4on435aQaXAPsA==
X-Received: by 2002:a2e:940b:0:b0:268:fa1c:106f with SMTP id i11-20020a2e940b000000b00268fa1c106fmr3706327ljh.101.1662380801152;
        Mon, 05 Sep 2022 05:26:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls4747314lfo.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 05:26:39 -0700 (PDT)
X-Received: by 2002:a05:6512:31c3:b0:494:70fc:56d3 with SMTP id j3-20020a05651231c300b0049470fc56d3mr10417083lfe.667.1662380799841;
        Mon, 05 Sep 2022 05:26:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662380799; cv=none;
        d=google.com; s=arc-20160816;
        b=dnqYEWVenpQFGROZyE9MmlnFlPKnsvL3D+Ivp4mQj+RD5PI0jeGa9UknMqM+X72Gmt
         6IkPH1ZgxpQ8Akgssaiw/X0gy+bSNzyeH4UguZho8HWRSz3MWqrpFRhGucKcMq+gPVpd
         l3i2zIKIZF/AmUBp4EZLxUITxBtJ8S/RBsJEY+xaKaACKGCkxjekUfJpiZy37Vj/pOcV
         tq0jhtenSNceQJNYteuLwlbjIbfWKLcg8o0Oax59Mj6uZwe2pMrq8XRC5O2dnK0kvDL/
         DS7shAehIldoD1CbtAysD7o+Wg0uNFK6kbDJ8ap6lkMBHNQpjc0PVXLR5IkLMAoQYfOl
         BBwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=y4+04AEFcGK6lJisKBf+d7wj7/tgJIfosEPW0CJiM4s=;
        b=smfF2J8mnNhL51PJxDQHBvR5kK/Efr7WDR+Ttfs8Xng45qxLjcoBvqc9miUEYxEIAI
         CkWzLiW+ghGkuWQkEAYZxnBQxj8Pnkz5/X1X631P7AahjGt0BNUa6F09aVKe8ropRCZw
         7eJRgV9VGhlQSPu4s0NwQqd8vJ+N2/MlRTjfdDCBv8GtTkDlGlLxS0EOokh3e7oD0Q8/
         63ld48rWLES3L8gADoVIhDixKScKRZAsArGLFiP5sfEVwftzrmJdq/KQdF6QrWdiJ3Xz
         iH4hQcNpj41p8urCd9oG8AmCgrdWsIKl4u2jy2LR3jxA+9y5gWP5OgTqoN1clhaJYrGt
         PFtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gBW+tZSL;
       spf=pass (google.com: domain of 3_-ovywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_-oVYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id u20-20020a05651c131400b00261e5b01fe0si402502lja.6.2022.09.05.05.26.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:26:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_-ovywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sh44-20020a1709076eac00b00741a01e2aafso2296101ejc.22
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 05:26:39 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b808:8d07:ab4a:554c])
 (user=glider job=sendgmr) by 2002:a05:6402:10d2:b0:445:d9ee:fc19 with SMTP id
 p18-20020a05640210d200b00445d9eefc19mr41641834edu.81.1662380799213; Mon, 05
 Sep 2022 05:26:39 -0700 (PDT)
Date: Mon,  5 Sep 2022 14:24:45 +0200
In-Reply-To: <20220905122452.2258262-1-glider@google.com>
Mime-Version: 1.0
References: <20220905122452.2258262-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220905122452.2258262-38-glider@google.com>
Subject: [PATCH v6 37/44] x86: kmsan: sync metadata pages on page fault
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
 header.i=@google.com header.s=20210112 header.b=gBW+tZSL;       spf=pass
 (google.com: domain of 3_-ovywykcuwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3_-oVYwYKCUwuzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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

KMSAN assumes shadow and origin pages for every allocated page are
accessible. For pages between [VMALLOC_START, VMALLOC_END] those metadata
pages start at KMSAN_VMALLOC_SHADOW_START and
KMSAN_VMALLOC_ORIGIN_START, therefore we must sync a bigger memory
region.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

v2:
 -- addressed reports from kernel test robot <lkp@intel.com>

Link: https://linux-review.googlesource.com/id/Ia5bd541e54f1ecc11b86666c3ec87c62ac0bdfb8
---
 arch/x86/mm/fault.c | 23 ++++++++++++++++++++++-
 1 file changed, 22 insertions(+), 1 deletion(-)

diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index fa71a5d12e872..d728791be8ace 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -260,7 +260,7 @@ static noinline int vmalloc_fault(unsigned long address)
 }
 NOKPROBE_SYMBOL(vmalloc_fault);
 
-void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
+static void __arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 {
 	unsigned long addr;
 
@@ -284,6 +284,27 @@ void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 	}
 }
 
+void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
+{
+	__arch_sync_kernel_mappings(start, end);
+#ifdef CONFIG_KMSAN
+	/*
+	 * KMSAN maintains two additional metadata page mappings for the
+	 * [VMALLOC_START, VMALLOC_END) range. These mappings start at
+	 * KMSAN_VMALLOC_SHADOW_START and KMSAN_VMALLOC_ORIGIN_START and
+	 * have to be synced together with the vmalloc memory mapping.
+	 */
+	if (start >= VMALLOC_START && end < VMALLOC_END) {
+		__arch_sync_kernel_mappings(
+			start - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START,
+			end - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START);
+		__arch_sync_kernel_mappings(
+			start - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START,
+			end - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START);
+	}
+#endif
+}
+
 static bool low_pfn(unsigned long pfn)
 {
 	return pfn < max_low_pfn;
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122452.2258262-38-glider%40google.com.
