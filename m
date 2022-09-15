Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2X6RSMQMGQERETPPCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D7155B9E2E
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:18 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id w29-20020adf8bdd000000b0022ad6fb2845sf562434wra.17
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254378; cv=pass;
        d=google.com; s=arc-20160816;
        b=GrEkwVcIQMNMd7ZwYz5RE3UEtZNgXA/0ZVH109wC6iYqAeYKKGBRSOXQCml90tVYvX
         wb9cdafnGoGv/OGktuiUq7OMcqkdNR35+7E1KV/WEMEF7A6D8fG+cIwJqo198xJ3Fi7g
         6YaOFK6icfDlxCdX1p+juTPnjMnfuDdCbCbZ/aFCLf5CyIeJbPRSGdSMKQgbxjJRa33a
         iUgK29PBU1LFlzqjnjmPMtTGT11OHXyGlW84xS3JMA3WWDqWGWvv1UdEPXIAbkMkuPH0
         j+msfmoXVBH2tyowNXwRvvFEYrJnKPQozOvrySQSh537uUNzJfSNovRG/4Y4dZWMSnnr
         qaSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=5VJPS8FMfMoQXRtVaqOwY49jBNZwnFdXkNAANs55ECE=;
        b=eOK02MQ+KxXzL78NP4IB8GLfTS9B/x/uSrT/G8NBSp7EYlPKm/41eds882jl/+nQDs
         1s+PoMXxbknUINCWH63qmVwjgtbk2n+YdAEtKiGO3iY5GFZXL6X144KCX51VWkYcZxCi
         DQ9b9PL42TSfiCFZdv8C1NnTHJH3iVgk0LokMviyjwJjOX0ZSouSlU4c6612m09uMl6M
         TAko7SiLBn+CnuxfcNUOst7u9zPd8AdcuAkOXIs2i1R6LkAa8Zw4EAPcca4Oqa8TIfdX
         Pr0SEv9oaeZDAycHFcsk1b4ngl/bj2j9+R9Bk+UEVEkFFzSG1CNpUhpHykvy5QTmB6jY
         kTeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TY9zj9hs;
       spf=pass (google.com: domain of 3ad8jywykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aD8jYwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=5VJPS8FMfMoQXRtVaqOwY49jBNZwnFdXkNAANs55ECE=;
        b=q4kKxsfBCDxEZGq5U/NfJez9QDqA3AiKf51wl7ds+DDbTkpfLk9ACKtDGYVTrs+kOR
         4qOzj301xWyC0GfX+Q4pQb9cpVObRhclQq23Ka0FCnmURqhdzmGiMBUKJMcjZx8Q8+Qs
         26a4l8Wwd/A3kfOrDbv6CfqxGRP/X+WWXsq0FdJdXRQXmK4Z4/Hf+U477s00+tThaGFH
         Th3HyCFmn9ztrY06tdr0BVMWc9Wg/VZwsk2S13L8T3/z8OVvKM1hqJ0QIBMoS6s6Kg91
         5O6HbIZaAf0W3GqrSXwYSKPdv6rh8hWcD8pTQ3EMCwUHNBEG1rgCZ1+5MFspa6FtM5dC
         +o5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=5VJPS8FMfMoQXRtVaqOwY49jBNZwnFdXkNAANs55ECE=;
        b=bCa3CoqtaBAU9japxRLpcFQ1fB1qIdTPhbR4CWjO0SVeOlen8YaPBaXK+WmkFaU2vg
         io8NfWS+ZFgsBFA/8CiKSbKUfSBGfnJBB7KuYKEOoCXqw0cKf7tQR+25835shtU9xoTl
         7zYMq82iHTHs3z4GvUTeScnROIwbOjmiLnAlCU7UV27ea6zl3WnVYjpL8hyM8ncP9tQs
         cX2y+iBfqjmzzUuhzhHtSWcuecVIyXNIc6ZE3+oIRJu+KD9LaZS34gE1eooy7fgDk9Vl
         Yrigg4VIsd1uq5lnoC4rj4TxWhRykT7K25diNcOvHjM4qBiY1qoxKQWCvpxYy05TKX/X
         l1sg==
X-Gm-Message-State: ACrzQf16aAZJfJDX6PpZGq5qD684ATth90luZ6/8OmBx+knnqRqM6hKa
	Rv6fuG+nn6eju5qTjCrVlcY=
X-Google-Smtp-Source: AMsMyM7G0ob/k8wJwkyCnTEiJX0dlW+NHVnbc6PfyjM2rOb4fZfR6pikJZrZHRjBZgQ1GD+H+aWZhQ==
X-Received: by 2002:adf:d1ce:0:b0:22a:36d6:da05 with SMTP id b14-20020adfd1ce000000b0022a36d6da05mr47504wrd.719.1663254378355;
        Thu, 15 Sep 2022 08:06:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f418:0:b0:3a5:24fe:28ff with SMTP id z24-20020a1cf418000000b003a524fe28ffls7308472wma.0.-pod-control-gmail;
 Thu, 15 Sep 2022 08:06:17 -0700 (PDT)
X-Received: by 2002:a05:600c:4e89:b0:3b4:8648:c4e1 with SMTP id f9-20020a05600c4e8900b003b48648c4e1mr218711wmq.26.1663254377291;
        Thu, 15 Sep 2022 08:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254377; cv=none;
        d=google.com; s=arc-20160816;
        b=hphQWX47QVwxhtNKAw69jOf4Rgll++ZJVSwuPMviCsyHEWRQcdeLVcI+4jfRXkJce6
         tUvIjTEYZ0M4AIqb7/ISuz/HwchARKspcrnxZkQgHaAtAbLZQkLR4BFzYS9wcuKM0MtV
         1cMYHkgPe78luU8rVOPlVfU504mi+bhROfrl2Kxt3MjQAdt3QHl2ypDttUCjshPpssZq
         InxrZNPDCgKEP6pmWYqZMfY3fEpmsIdp5iOo5CWmNnkH0ENsNRje2gMVnWXalD2BnXfX
         ePN3YEf1QiXwmXU0VCfwaX4eQuRyry+xW05/65gCQM8fPdu+An7lQRDsuhFj6H1miAHZ
         s1SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=y4+04AEFcGK6lJisKBf+d7wj7/tgJIfosEPW0CJiM4s=;
        b=NtdhJxur7HZ0NI+Au5kFRs9xVeO1e7/C/pkousJ40UDbgfTaL7Clddq3Yj2TePDzgw
         EOraZASbvsw3M0+6rSwqh7dihxUPjhjDrIGZZoy3DQ6fpgWJL3Bnc8ZAf1GX3KHOZATW
         d6QcuDe0oEuIWBNqrciNvbu7zN7QdcAJoZWGBrIJJ77j50hByvqZMQ/msWjTz5gOrvpu
         hR5A/O3IeUjADKKN4qktumR7/juDddRWkgjqBMXxsvg2OiJH3sHuTwa6AiGG0v0K2CVo
         6PrjxDXDcgC9TZex4HGt9Jx92sb0PD9DI/nh824qT+IYkFQtDviT0oEDM9jK2ikXBIxx
         snHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TY9zj9hs;
       spf=pass (google.com: domain of 3ad8jywykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aD8jYwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l6-20020a1c2506000000b003a6787eaf57si50322wml.2.2022.09.15.08.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ad8jywykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p24-20020a05600c1d9800b003b4b226903dso674402wms.4
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6000:68c:b0:22a:bde3:f8cc with SMTP id
 bo12-20020a056000068c00b0022abde3f8ccmr71217wrb.556.1663254376855; Thu, 15
 Sep 2022 08:06:16 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:10 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-37-glider@google.com>
Subject: [PATCH v7 36/43] x86: kmsan: sync metadata pages on page fault
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
 header.i=@google.com header.s=20210112 header.b=TY9zj9hs;       spf=pass
 (google.com: domain of 3ad8jywykczm38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3aD8jYwYKCZM38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-37-glider%40google.com.
