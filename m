Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4V2RGEAMGQEG4GSEUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E2443D9EF7
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 09:49:07 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id d28-20020a194f1c0000b029038a8405fc0fsf2265537lfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 00:49:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627544947; cv=pass;
        d=google.com; s=arc-20160816;
        b=il7gjRf8Zjvem7lf6UJXhKPfZUYOLpZfys5YmKHSvj5C4CKV06lbXbQlMq1+hUNQqM
         a81rU3gDAAfLYwM3nMvf/pw67XNBSAaA3PFhdPz3FbRQSsWoU01DrgnGJ9cS9IJc+Qxs
         Tb7qD3Z9eouiqwAaI6N3O0WRp+ikI+msNXevdzC++UkTxi6AdrygZ4T6yBt3P/mxp+99
         VbmCJlFQv6dINKiblvfj9lE/NxiMEnNFGhtcczPrTw89YanlrYAb8b/W4apCcJyVIstw
         Hopb0NGdJ06Ivt30H6Z4PFbroVRTfv+JtdAlCV532oF/kxmhfyFUtAcj96AVG2ZI7h+Y
         H3xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7siEia2YiAfKJKtQDKWLHLfXUT4Y0Lw/Oa3hdEDP6d8=;
        b=hTGMIAs81IYAk7GMwqz69HN6LnpstLjJq/YB3/YnUemOgKffqm0YQVjVu9tAJL28QB
         6boRA180vbCTaEa/KSJUCg5sljRvVVatiubGk3/wPB+an7ociNw0AYH+7a/g+QNOfhFq
         w57W1QhE+SpTKfcfGy7OrrztAlTlLpN6oyNLMQ7rZ8kN8UmubEHstWIQ30zFMBhr44+T
         1Fnu2dLJLCX2UGTko5ZXa4GLtMZ4Z6pxH/dTZMrvAQKDxXOtKuarL72TxttCtKyQFVkw
         2J2CbUqWJg11PWdJbjwZVJghEANm9mSscsW380gm0b3t03miQ+OZ3Y2Rl0OIl3BgOCjJ
         9K8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjwxZwUR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7siEia2YiAfKJKtQDKWLHLfXUT4Y0Lw/Oa3hdEDP6d8=;
        b=MybrhEruS0H39q++PiK/Nlh5Rnk0Nygkmy9vm8NNa5mL2MGbgpuq9cnCxcXHize803
         SDNkg2ZlkMEsPgB79n81tgaSardJQFQzWWFBHHfy5etWO46m4pYBAxmV/yA09F84/ODJ
         jIsu1teKBG6DsRPo8FFtT32AxZCq7zJ0m/XygyN6JoJ0MwEIUH+ahxyX3W3i7n8eoIWN
         ttSGYERXr1IE9HKbvBtLF9MHRg9YqM5OW878NNzn2XgYwe25sSqKT7wCns6fOqLyDZqY
         X6ZqJVkXyqQ86na10XwROsurEPMORokcrR6WVhzzpKvEvWy+JK/Z+Od2Zl/OsPAbd72F
         W9dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7siEia2YiAfKJKtQDKWLHLfXUT4Y0Lw/Oa3hdEDP6d8=;
        b=kmxiZSCwFDnLUHk1lgTsvX2XphfG3E3OP//eAhKhCMroxeaVLcjtnT5qQeuMhzVhNs
         OLYFTg2Ld977YA2erg/qBfKmKGoW4BVwyabLdQQq+uoqb/y4oOBpXUmDvUBtTfezYmg2
         X7NXvK+RVAgfHjl/lZfIq3POaO/W6eG50GGuDZlao91VkxmTFPqp8Zj4ArMQ2iVH80po
         6QgxnO+3miq/Ch1OSfnq4/USaW53yzB8IeP+0koda4ZN2AbdA/ZM+hqTR0yrEBg9DE/B
         NO0RszkzNoivBccuYkqtTn/O6RdGat6R1wRbcxJkrkZ3ZL/x/inHd8IUloQyhUz49x1G
         nODg==
X-Gm-Message-State: AOAM531I4CML8qTY230XZHQN7A44EvoRpfvOpdyArTiJJXsYr1clymi1
	asOF6uO+JMUB0xNYnkR755I=
X-Google-Smtp-Source: ABdhPJwtwRc/jf6LRfX/QfqRgFVjYes2EEwd1epC/rDqBSPypwFfLtaubE0BEiOiefLhNxWMxuEcvg==
X-Received: by 2002:a2e:9cd5:: with SMTP id g21mr2090171ljj.99.1627544946963;
        Thu, 29 Jul 2021 00:49:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:36c2:: with SMTP id e2ls3676848lfs.3.gmail; Thu, 29
 Jul 2021 00:49:05 -0700 (PDT)
X-Received: by 2002:ac2:5dd5:: with SMTP id x21mr2789002lfq.31.1627544945823;
        Thu, 29 Jul 2021 00:49:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627544945; cv=none;
        d=google.com; s=arc-20160816;
        b=cxKsE/4HJL0ba5Hm1zyJhvVPjhcl5jjZJQzscKggM7QEpG+PleXW4qD8Vv6b2gh7HO
         ho5OVHrjp0FkBMFWK268Na9uak7/yY/LicCfYD+jVpU24GBXohx5cXPNNjYA1cPWag4t
         59HmtetpRETo8iyz5zzWC7cO+JKWhdNpKg9y+le03Qxs2jADKp0MJG72VZibSet22Dd3
         LEDTySt+nn1lAsWlx/MEHgRJqCki8TX5ODLwW9AHsyvnxZT4rkC0N4da6le1SVOXXPXe
         5cyb1DrFgjd8oeq8wqqLuh0ZkOIez8HnwDjb62zgVOy2p5t+H1w6DroDTS5cgZk719TO
         2bvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=L6N0ezTtWFmQj4Q9ef8/0d56n3pMY70Zf97no+qDSJA=;
        b=cCsBHHOpOjPYqBZm18swJY+xKRJkd3H6946oByJShXZyKxCK62DjyXgzO6b25sMEJ0
         xW2ASGxZ53xg3rExcCBEGPHvenw/3ThY4MP33Nz8FWbwisdU8Qw8d+Gs+qR4M2j+6J1J
         TmuB+kV24NVq+iREeePKaRi/ESesYMWM+rEMsFklXML55UQg1GOg2WDHSxA0At48AMG1
         frAsa1FcctOJidPE/mdIHdEJLNdzw6+oaD/kVfjUNvc6P6iOleNxLD9vPaXBZqILYXLk
         wunvW4LyqdRtEAt7UScSa57KDOTAqSM536eJy2jdn0X9TrjPVlNsDirwkdnncpnCKctS
         Oqkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjwxZwUR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id j7si124908ljc.1.2021.07.29.00.49.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Jul 2021 00:49:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id b11so343807wrx.6
        for <kasan-dev@googlegroups.com>; Thu, 29 Jul 2021 00:49:05 -0700 (PDT)
X-Received: by 2002:adf:de8a:: with SMTP id w10mr3331505wrl.61.1627544945144;
        Thu, 29 Jul 2021 00:49:05 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:377:4a06:5280:39bf])
        by smtp.gmail.com with ESMTPSA id k186sm9573131wme.45.2021.07.29.00.49.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jul 2021 00:49:04 -0700 (PDT)
Date: Thu, 29 Jul 2021 09:48:58 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Heiko Carstens <hca@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Christian Borntraeger <borntraeger@de.ibm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: Re: [PATCH 2/4] kfence: add function to mask address bits
Message-ID: <YQJdarx6XSUQ1tFZ@elver.google.com>
References: <20210728190254.3921642-1-hca@linux.ibm.com>
 <20210728190254.3921642-3-hca@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210728190254.3921642-3-hca@linux.ibm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tjwxZwUR;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Jul 28, 2021 at 09:02PM +0200, Heiko Carstens wrote:
> From: Sven Schnelle <svens@linux.ibm.com>
> 
> s390 only reports the page address during a translation fault.
> To make the kfence unit tests pass, add a function that might
> be implemented by architectures to mask out address bits.
> 
> Signed-off-by: Sven Schnelle <svens@linux.ibm.com>
> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>

I noticed this breaks on x86 if CONFIG_KFENCE_KUNIT_TEST=m, because x86
conditionally declares some asm functions if !MODULE.

I think the below is the simplest to fix, and if you agree, please carry
it as a patch in this series before this patch.

With the below, you can add to this patch:

	Reviewed-by: Marco Elver <elver@google.com>

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Wed, 28 Jul 2021 21:57:41 +0200
Subject: [PATCH] kfence, x86: only define helpers if !MODULE

x86's <asm/tlbflush.h> only declares non-module accessible functions
(such as flush_tlb_one_kernel) if !MODULE.

In preparation of including <asm/kfence.h> from the KFENCE test module,
only define the helpers if !MODULE to avoid breaking the build with
CONFIG_KFENCE_KUNIT_TEST=m.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/kfence.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index 05b48b33baf0..ff5c7134a37a 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -8,6 +8,8 @@
 #ifndef _ASM_X86_KFENCE_H
 #define _ASM_X86_KFENCE_H
 
+#ifndef MODULE
+
 #include <linux/bug.h>
 #include <linux/kfence.h>
 
@@ -66,4 +68,6 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 	return true;
 }
 
+#endif /* !MODULE */
+
 #endif /* _ASM_X86_KFENCE_H */
-- 
2.32.0.554.ge1b32706d8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YQJdarx6XSUQ1tFZ%40elver.google.com.
