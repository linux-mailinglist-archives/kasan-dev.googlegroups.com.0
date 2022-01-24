Return-Path: <kasan-dev+bncBAABBHWVXOHQMGQER34L4ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F5914987BF
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:23 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id g13-20020a056512118d00b00436a446899fsf3718291lfr.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047582; cv=pass;
        d=google.com; s=arc-20160816;
        b=F3xAQ+lEfc5u+GGi9ROoKeAgCpA9s1v6zLn7dzAegao7oGCOVm7lh/4xvdU1eFqm3O
         zc7rNjPWOxe/F2TTR4gVGYuCW9IR4RamB1+MYL7fgtBeIUSPR8pUhrEgdP4o9xJVPFhm
         kIHQDRT9YfFw09zk/A2w0NYtfu2B2fVhCFO6R6ZrrjaLM30I7AiWY2ngmQcPxZBRJhPW
         6reJH94wf7/QaG1mAYOwGoWjOHeiJRxJAUzwekUwoEI5cBefxomaoAP2gewAIVs5Zc4l
         TMDh+AKRmNaqhY9LZPNlecf897WeR5ppkjQu5knMl6CJlgaEL7Da6o750qaSuehvgziQ
         bSaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wmX4MBSc85PJQF3eGEsD8BzcNQ2VdqjLuWY2nT6ZJh4=;
        b=hw+WDE1kIqTAuPzeDasUmpgIRIm+91VJNIInw5fFNcOYDFaNaIsakmyjCcVrC4Qt9o
         LOthpaWpqeni253ZqEjBE7bVY2/T4ZNvIgKo1k4MAXB1idDrYivoVDQ7FoA9wsFKYICJ
         7l5bDOrYfANMKfgUOr90584exMkTvGcGaIurONtu45YUArnOawsiuO7xzOZouwK+Lb/4
         s2Ji2kHkJLfsrwziPKiDGVntLRf+vCa3ONHRX6PI7o76NC5zo42eTjHgsNxf4D3xiWsc
         1lPho5kh6qJ5tigu9GpBQ2fZ1RmJpe16RMC9Gc71SwQmWK+bnLkzxrTOQyvkiDA+goFU
         TjcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FjC5A+7G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmX4MBSc85PJQF3eGEsD8BzcNQ2VdqjLuWY2nT6ZJh4=;
        b=rduoNggaoTBC81nIMXMfddLNGbtxnrfF4kjiCzAFSG0vWKfITV8ko055oKx2XMDZzb
         bQi6L4TrcrQq+hFZnCwP2YBu8w1Oy4fiJb9s8s/Zh01Ij17om0reCWcVwtjHbIfkC9zH
         OW9zOWz3QwQcuK0cJEUwgx+e18WpS59mRZtFGxJqR+sIU0ncamRuoSoi4F4IUulUgioS
         6qQduc5G9kowKZHqt01uXLcpglUWHuH2Ugq3yKHqOvEtn1XFUkIwkgxYmEZCNsIqWxDR
         aH9lMc/X43G/nG7o2bscIIRTInyieNzwT2d3sWHeooYidwVVJMlCpg/6s3S9LiIWSb1/
         Xqzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmX4MBSc85PJQF3eGEsD8BzcNQ2VdqjLuWY2nT6ZJh4=;
        b=cEunpPDZHdmbo/zXyLX81PRF2FaaQ0jucn1I5r766bkoG0bofDM/CfhdYwoMk8pyIa
         gAclMgmDDsGjdnDADFw6QzsBeL39ENkp5AzFaybehY002kKAP+4oXFr1+ZlY8AWcS+70
         gw7PYjrzxqVWpqUcWnXjVeNfyPrpL+Diu2qJSkKwBeLDB63Wx4GVJulgtIBs+0/Es3ZL
         zHxgq8a5W30uiULYqdrywGW+THYPU75UauyRo5XckzgCGNH5Tv584CjujamjZpmojcwU
         l3i2JFBJV4k4vFM+Ar6mhoc7L4QQrmoxoK5WSoLzcu6VIzRMsYN+nMjJ9BPt9957CpjS
         9cgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304t+2Vprjhj13iiWymwNWA7z1uJb38eX09eTrh6PqptMFPcuA7
	6kXip4unNmXjZYLyKHmW42Q=
X-Google-Smtp-Source: ABdhPJzBJkT6oRCWEBM6rYlBFZmwMzA+bHd+fK3kATCANPUygzDNt6ehcv/GlIPS7oiKsnDnqFZRnQ==
X-Received: by 2002:a05:651c:882:: with SMTP id d2mr11810917ljq.311.1643047582680;
        Mon, 24 Jan 2022 10:06:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b08:: with SMTP id b8ls2483948ljr.0.gmail; Mon, 24
 Jan 2022 10:06:21 -0800 (PST)
X-Received: by 2002:a2e:8511:: with SMTP id j17mr1874412lji.437.1643047581758;
        Mon, 24 Jan 2022 10:06:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047581; cv=none;
        d=google.com; s=arc-20160816;
        b=bSDx8j/KeSbb1w59rBRnSxGxfQnEklGehOhgVgkOwb+VNB0GR7rx2EtL1bvzvecedK
         fN5Eo3+l0FesLPwtzLAKXgoZRnyC0A3StF3/Nk1JNkXXssihw81M7nNWm84+Zkhrowkn
         mgOk+gFKlc13SktDtRWXRTY7PzYJjhAuEVEpM4d7oZ+lBXewGu/dOPxJx1QPU71R4ELo
         6jsOtYF6KZ1KGseWLPQPH9kniFSeWg9xYiHyvRpOIboA+jmDg5q8YF/RVyi8lFWI+C3W
         BFTreBhpP68UCJJCTES+6XR16N95J++Jsi8GHpf0rAee/JJSaC/aOXGLXlHftF/bqH1B
         DtVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zMk+i6psUWRrJkriJ76ixSA3XRodREnil0b2HWyShlc=;
        b=q+aTL7/ANXCf3dfMp9QvYaHRTfI3XW9h+rZEz4+vKfDhySSd72xXIFYjTkXF51MqWd
         rWo0UrjI4gutflqA1Qc3SreJBfl2Ag90aMFUVM/yu2T2sLIYoD8wnVh1zQy5GYciniA0
         XenAlPxylgfG8GaeNLTDnG3Lt5MDG+LHEjZmkfdCuPqX+1mhrUxC7Em1aBsLgU7O43C7
         HM6X6hq1Yg8Pn0c++JwLCSjAdPlfG2QtYiHvjfi9ovJYLuvET6AeZljKkqcs+kMjC4QQ
         aMsjSROyxUp/VQSZmMakceM4tTzDhVauqaYEjjJKqSCkTUA8O7JpB9gN/dp3usy/gZLJ
         bDNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FjC5A+7G;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id k25si253158ljk.5.2022.01.24.10.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 23/39] kasan, arm64: reset pointer tags of vmapped stacks
Date: Mon, 24 Jan 2022 19:04:57 +0100
Message-Id: <698c5ab21743c796d46c15d075b9481825973e34.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FjC5A+7G;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation in
arch_alloc_vmap_stack().

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the SP register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP register needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>

---

Changes v2->v3:
- Add this patch.
---
 arch/arm64/include/asm/vmap_stack.h | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/vmap_stack.h
index 894e031b28d2..20873099c035 100644
--- a/arch/arm64/include/asm/vmap_stack.h
+++ b/arch/arm64/include/asm/vmap_stack.h
@@ -17,10 +17,13 @@
  */
 static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
 {
+	void *p;
+
 	BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
 
-	return __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
+	p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
 			__builtin_return_address(0));
+	return kasan_reset_tag(p);
 }
 
 #endif /* __ASM_VMAP_STACK_H */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/698c5ab21743c796d46c15d075b9481825973e34.1643047180.git.andreyknvl%40google.com.
