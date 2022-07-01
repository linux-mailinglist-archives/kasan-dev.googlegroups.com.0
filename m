Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPEH7SKQMGQETFBCCQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E7A7556353D
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:00 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id az28-20020adfe19c000000b0021bc8df3721sf416141wrb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685500; cv=pass;
        d=google.com; s=arc-20160816;
        b=e1aun8HB4Rr1y6jDPF5boyoPRH3bGGCHoGT4OsuP9mVntwVsmiaBc8amn4dbyaEkzf
         OXesPDjNfiKU45rmFg+cJ6hkwFhz7ASpAc/VFAJ0t3SF/jcjn9aBH0ZWay5MUMZGFLsV
         KMx9lRsp863af9ZkDGFOaBL+ZAxOnAiK4nLPacA3Q7yBpbPSM3wJK98oRbbIwtu3FsLU
         cKteGJUTLJohHIPB8uBJg6axjQXtAQXERKuY+E7ZYinUpW2IXd4tXkYAgeGuMjucY8Kt
         421mKVqjCKV5kgMiR16vQmTGWyzsrsCLjOFpFcdWQQzSNHihAtLvvGFtOq/c5Q4DGkov
         1BDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=G8DTG8V6m8NouRBxRRwiBI1QL3H98ulqbroyNK+c4NA=;
        b=kDO9QJ1wUZDOxVnrVczQMxQdOLu4y/443rD5ZBGZL9v8Jy2a0Dm73EAiHTWvfdr9E2
         7OreWc8mD1Zw/hBQu+aAPYjJAlRcxJs9SbtnspJR1CiRoXaIwWreLc8cpJnnbeXMjgwy
         chOqoxTn6FS7whSAJXY6CiRGpfnMk9XfHNmasHNgBuXdNB7OC0X+F6IsaHlj3Jh6w7jQ
         dd5NZWHHl4pHi1y2CSaexG+KUoRfrd7f1HzbWBUkh8NFYWSiMOp28v46dIoalYeamxVi
         ApG78AuPdZXZS1Y4YCz5c2+pMkQD1ddmB5OkIL5dosXEGiT39LSB+WHbMloic19Z6A0Y
         FHcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R1eUqKBb;
       spf=pass (google.com: domain of 3uwo_ygykcdoche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3uwO_YgYKCdoCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G8DTG8V6m8NouRBxRRwiBI1QL3H98ulqbroyNK+c4NA=;
        b=YXQrAIpkDLJZrU/UC6mvSfhmXiWT5NWOmyQ7IFXgJw8Vt8oOpo086WicVTN9cQMWQ9
         JcK/uqK4Iussqi/bQjnAbMDgFxONRguQB2epZQ5W9JzJcCUTc3/AOSM72u/pSKoV9uNU
         4ydXVSrRCe1Bo0b63AWVkJQdl7inCBKEg+OGGiqL0x1IQB2HpbBdKx9SC/s2hjrR3IXI
         76qW7E8BRdfQyRPXVT/8GH3OQdbxY8TcSwnS6G+0DM1oMnleXuvG/BrRIfUqAB2Mthu5
         FWduAoKNRDx9XhnUnHIbuwGoipezlZJD8+FGZ0z3rjm8IfsgQCWr/tvYc8oFD5TXGDjw
         p46Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G8DTG8V6m8NouRBxRRwiBI1QL3H98ulqbroyNK+c4NA=;
        b=sZBVKKkAAKY1+uEqiywuOglZEo7GN9vupBije4XGf4hVy3mvD1F18C00U0KlvGa9EY
         /OpVHwzPtIcldWq3l1YMLAL7JGF1ZS8I+92sEGseSIetAHi2D0+Z1ApqVFj4yDNIe6Ov
         4qMGP/fUOoKW4z7rv8w7coX9/cZFQpxqZKBUhO+n9Je/jY1j5mZx2jsnXsbAGRKb+4do
         kzGID+lRwOPhjjQYZWpgNzy3WYWO8V9l0nU1FXLF2jri0yzk9YDEulQm0Eco6O1kHwYI
         lRZB5NX4HQPzDIWH6Lea6JHd29PpJAeZ7ih1Fj3/mXBtq5CElLbR1FtpSDcvi3dK9O66
         L/gg==
X-Gm-Message-State: AJIora8khY+B8GpgL4Krzog82uwp+gzhmYjPY4FNOk817VwSt2Jrf/SB
	LUCQJUXrcJkIsPR+cnigBw4=
X-Google-Smtp-Source: AGRyM1tqyqrx/bjBVrarXlswNwuivQO2SEf4qz6Ri6vFcrAfaxHRIrGSGF1cnBYONVTe8XNwuk9kuA==
X-Received: by 2002:a5d:64c4:0:b0:21b:a3a2:d64e with SMTP id f4-20020a5d64c4000000b0021ba3a2d64emr14656138wri.571.1656685500513;
        Fri, 01 Jul 2022 07:25:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls11376740wrz.3.gmail; Fri, 01 Jul 2022
 07:24:59 -0700 (PDT)
X-Received: by 2002:adf:de02:0:b0:21b:953f:27da with SMTP id b2-20020adfde02000000b0021b953f27damr15137722wrm.376.1656685499688;
        Fri, 01 Jul 2022 07:24:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685499; cv=none;
        d=google.com; s=arc-20160816;
        b=Wboh2oSc0pl/hmdgWZ5idz4iWyZidlWqXfII0Vh5C0NL/A0SdPbdEcRFj7NfqNIJvp
         dk/+E2h2kc9RVtsejgj8KOTc/JC7VlWpQ4zvmLehcskCYEmhxlAw/zVVSsIYiKi7QKrq
         zj6N/ARFBADYyXplgh61g1yHuId7Or7FrGYs2/uuaJOrzh+UicpTJUT+HVtkMzoYsNCs
         f4Vf7x26tSO0YNtB3+5kwNBcqJ98U4F/Z10fuTZAAKHs+1iGi63G3nVxNUslafoA693u
         sw/+fITCI1JyBNCmojhyTpWScxDou43DyAmlKMybYublNR/bApI5Mra4IARM96gtGtAS
         LSwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Hs1LG4gEZrL61QQbW1yHjuo38dVFxHr6aTHqGRd2nIU=;
        b=Sx2B45d9P0Ig+J3U//jntzDdEcJynfzuiMDE/3tsDXZXEbe4pXWqqguAOOzYDkUoHQ
         ufMbyl1Gq6e3cTZn2aIRTjoLD7pkU3PWwtAXxwZbn3rkbyxK/IbfIqMo6dHayDKTMt9f
         18Mh8gr5fc5Fc+fCvoet9WwHgnFWIU+/vxcWoUXwQYSNjo0dxbhhnPeVSgjhNuPMMGD/
         BiLyuggtR3w8ZmbydCoKCSsHePgHVpswloymxVeafLemPtgpHhgA9X+3Kr9i1myrIWW8
         kDjL7em25fAvzPC/Gy3hGs/bKkV955WBIUiwS6JLo8U3uO0bavEaWMr7kgSZuKxDz0r1
         CXiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R1eUqKBb;
       spf=pass (google.com: domain of 3uwo_ygykcdoche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3uwO_YgYKCdoCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id y16-20020adfdf10000000b002132c766fd7si810287wrl.4.2022.07.01.07.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uwo_ygykcdoche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y18-20020a056402441200b0043564cdf765so1892876eda.11
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:59 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a17:906:846c:b0:72a:4b4f:b1b1 with SMTP id
 hx12-20020a170906846c00b0072a4b4fb1b1mr11506007ejc.255.1656685499239; Fri, 01
 Jul 2022 07:24:59 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:02 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-38-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 37/45] x86: kmsan: sync metadata pages on page fault
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
 header.i=@google.com header.s=20210112 header.b=R1eUqKBb;       spf=pass
 (google.com: domain of 3uwo_ygykcdoche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3uwO_YgYKCdoCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
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
index fad8faa29d042..d07fe0801f203 100644
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-38-glider%40google.com.
