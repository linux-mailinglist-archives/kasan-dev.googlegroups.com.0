Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUWDUCJQMGQEQGJRFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id F18A8510423
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:10 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id bh11-20020a05600c3d0b00b003928fe7ba07sf1092783wmb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991570; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ir7C/Bgyvg0kU0RKUnycFzGt4uA9SmB/U7fQ33rD9OLm/+/ANerSZ+aiJjOjgHE9cy
         rmHO+ggNFOzWEkcWeKHDFgQQ/XUlPkte+x9RUZr0X4IdMiYg9HLbOnI/xCiSiy1I9Dz+
         IFxbmEN2kSB9xjrCrzle6WPrK5NjMvI47MzTQEKfGGVhFM96kXEGOi2SpVsXfozDed6f
         vYmFVCzcimnM7iWsJ8go1bACBVj+afrJcS4YpKGiV7uqSiQeMWg/Ma2zOcB5bsgrWnpZ
         +FeDxBR+Bd5JFMXmSimdpa/ZIIy87XutLHsBzeIX7/IffBtdHwPbHiJNAUN2QnfM8SLo
         65gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9fFdiUVH+PsbRKMoBHdBfuKeSunxScwdotlATK0HwXY=;
        b=cmzFGt13PWcse5ecAuRlkPhXWyTUZ7aGtRZnu+zL4dImHyIgkFeRZOT+6DRcRmzVJ+
         U37McXejxTaP7Je75fQ5dBtSnUPNZacrdgyCYvejGjp5ObPxmEjj0SQuZ0FAD+LVaGoR
         517M8l1v6tXJMQPWV0TK05o6xmwBjewCVXsKN5ckhkLKNHnX+gP3PC+MyTcsemSBlq2H
         yIYGeEtRi2k6XND5M9Ms2Oenvs+skt5Vw7ByXUm9dvUq5KeASS8Il8Tx3flQJzyCxnzO
         jplBuyWSgC/V4e3i9DYcS0lA3JGo/gTPb4znL4GR7ZESY2INkeW2RvTZ24gYsWuQVYhE
         KzNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fSZ4zfvD;
       spf=pass (google.com: domain of 30sfoygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30SFoYgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9fFdiUVH+PsbRKMoBHdBfuKeSunxScwdotlATK0HwXY=;
        b=CpcYThdRCvsIcbd77N49GytXbk79N3uq5Wjd0eZM2xQY6LnUjINpMPI89trI1thUds
         dpurO0nvbdHJLs6TIlXBVMFNCQgs8D+xaWrcgX2mTUHC1BMBL1T2arcXGOMA9drqg3Hf
         Ae+2kbTyECFSzts9wxLJE2nTgad6YeoO5yYYUQxlHEs7TRx2+LguJUnWfxBuSsI101eC
         wzb6/eh81uKXbN/B/qwArALVkqT8kB7VHiVYt8gIU9eaw7LyQee4UMKbdxE64xc/kgo8
         5sIm5Ixh5Y0tdHIir3crzM9wOKkTjKT1wgOa0+7+xqBvdJYFCxJ01tTzfTtsj/zA6PLQ
         PwaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9fFdiUVH+PsbRKMoBHdBfuKeSunxScwdotlATK0HwXY=;
        b=EbMOgqudSAz9ltziWl3XZIrLOHsoGxxx9xwXNlfbYkCkjqQApbw4SWwbfr2AueCFDW
         j9WVyXDYhyUpbrOmhEJDlzPx8BmoFNW1NbFTMVoaKgSEkD7ZMDc4etg6PYdc9xzQGYBH
         wctLJB5BRRFSJvFDgRNXd8n8SrHC3nFUWTjAu2Wp/U2HjMb0xjIpale9nIguHpz6e4y/
         pAASOkYeUMfiiIOmp8cmqXkEPD3iyrA2YJJsmOyH9gFmnVihiq9FFQZGlkM8McNd2gf5
         gL0V71Rpup20JDPjlJvGxoHMr2LipOpGRcUjC0axcD4QArTRzXZfO1uhad+L6Qhn+yRu
         nAEg==
X-Gm-Message-State: AOAM533O7LHkcev4OoZjS3+xJ5Ji4C+VekudybhgQqjwu5X2gqlGEbu/
	hzyOUWmGm/R7rYbNrrpjEGE=
X-Google-Smtp-Source: ABdhPJz5dLf2mwPPnHjcXaYTDIJqNfb0vefpNM97qCXxxqdm/zZ9TwWiqKu923rik1Tk/JFztJZDsA==
X-Received: by 2002:a5d:4311:0:b0:205:f26b:fb98 with SMTP id h17-20020a5d4311000000b00205f26bfb98mr19459498wrq.202.1650991570799;
        Tue, 26 Apr 2022 09:46:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f950:0:b0:205:dbf5:72d8 with SMTP id q16-20020adff950000000b00205dbf572d8ls1005247wrr.0.gmail;
 Tue, 26 Apr 2022 09:46:10 -0700 (PDT)
X-Received: by 2002:a05:6000:1110:b0:20a:e113:8221 with SMTP id z16-20020a056000111000b0020ae1138221mr5425275wrw.271.1650991569975;
        Tue, 26 Apr 2022 09:46:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991569; cv=none;
        d=google.com; s=arc-20160816;
        b=WX/hyaC0esmiKksQnwfXICpiBpp6Lsz9xaEu81dUE7Ef4x7jihuRKOjDnJKhCEzo38
         hsujWOH2f1JWYrlU6F5QIQsLWXce6j379R3S3m7Ekc9Cpn30JMNvK6Q6yGK31CnrvFoq
         iArZNL3PwTkpT/W91z0N8WIbn/8j/DSRKjKjioyfiB5s2q8MrkmybCnoQ51Syxcdg53a
         LU9yayfawoTVVgFkhUgzcyyJapuQkYda4P6bk+bxqjaQHWtVcL3/J1grWy5fMT8/mGlC
         sRmLmQXLGw2LO8zxxN22qbwDrMRENDnv0CgApWIeEpbx0bpoQq8L4e7EsGYpcA0qnO8l
         iXNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SGOwGjYq/2PwacKh0/9At0yFevcHrzg9FDlShmi+vnk=;
        b=FW7pzjsEXP0dn2E4f6NvnP6NW1BhxjUsxAE3eutWr2KrjWrvu2LGTeSSJoEprhWxQB
         si8WMS/HO0x4wHgacXgr44Q4m6QQvVjIQsRC0XQEIOSzmkXU3Wznptw+2yRQLoFoB0kS
         3GEAV62qUHs2G0ChoGEn7wWTpg/aTyYJ+iOEqtBf+7yyGqIWCVtt9roMMdz10pz7tNU8
         Y0H79SLFngcZjZiwOA+cISwMygScrfTi5T4iDBhjnwyeJ5anqOExTiMKPuxSsD5iSCJy
         wrZwh57skRUEjhYqVlzgF9g1PGlLAbhvWqAJCUGpML6kyiCwz+JzFDwvLvk4lNvCtuvJ
         ZalA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fSZ4zfvD;
       spf=pass (google.com: domain of 30sfoygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30SFoYgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id o1-20020a5d47c1000000b0020ae674a22asi118048wrc.2.2022.04.26.09.46.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30sfoygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id nd34-20020a17090762a200b006e0ef16745cso9336078ejc.20
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:09 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:84a:b0:423:fe99:8c53 with SMTP id
 b10-20020a056402084a00b00423fe998c53mr25385277edz.195.1650991569448; Tue, 26
 Apr 2022 09:46:09 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:11 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-43-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 42/46] x86: kmsan: sync metadata pages on page fault
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fSZ4zfvD;       spf=pass
 (google.com: domain of 30sfoygykcc4052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=30SFoYgYKCc4052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
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
index d0074c6ed31a3..f2250a32a10ca 100644
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-43-glider%40google.com.
