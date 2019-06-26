Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5EBZ3UAKGQEYCFQBQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 66E9356BDB
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:28:05 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y5sf1855219pfb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:28:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559284; cv=pass;
        d=google.com; s=arc-20160816;
        b=hffDkCh2fCmA1Hqz2NbH8yiMEt5i8Ggj+yd+WtpA86f2go8zGEg8BnsebumuCMX8HD
         daJz6Rs4HKOy1PQnbPuIY322Iu9IuD7wjVILSdkzTt9dXJD3f1TLJVVNNVfoD/2HxjTa
         8UdO7Nuc1iD79It/rNAgD6/14GP6xzFYkUtak+mM0wpEBjCMd6dP0cwk5agwv/Vc28VL
         A6h1B8EpGjp+5dgM6W3jhTQjbSmLOlbU9jbrHxMNTPy5sSia39s4zsXap1cQfq+5unS/
         fTN5SvNfwb9r/o+tc1PbHIexldi2rTj7QpoCB7+d829KMDI4BXglJoXzcoSuti9z2MVP
         b25A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SFkIMGfej++tW1fm34B9oovKy0y64yFd7oFw0n4CneU=;
        b=Cxi1x9KD0XtqGiZTwwycgkjuXFc4IwqAaKk1ueTG2yHAu14Yi1o3DbgYFelgG32H/g
         slIMBUFoREq94qSpxr54ZPC5ER8TQOsLTEsfGBFRu59qAcnNdwXj5xb7CW/YMs8e0Sbc
         UbZF57wpq3e0ZISwJm+LR56rRJBJsQlfpcGrP6GCsX7pxZsd0h6ZjaLKafDg1ovMfbMm
         qvRM6vZBR1Fsw3WQLMjKHfdEwm5aJBaPqBtQSD0NmEksWZuXF/P8jSTRGKAwzcamqpqK
         jIQI3LswN8wkcV/ZuwJV/bjUndcBw9Ckiz0JU8gYVQ6BFwvxCiivOsPyi1PxtPbwqvy3
         MOtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gU068bo8;
       spf=pass (google.com: domain of 38oatxqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=38oATXQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SFkIMGfej++tW1fm34B9oovKy0y64yFd7oFw0n4CneU=;
        b=jK22dO896CvIxK3Y9Vkkc0Q5pJv/r5xWURA6sqEe5paEPWtas0EhyQqNsbewx1+gBK
         AK//uoUO5geJww8feYclFc2ptcsTZHTImeLMM6ZmPdVFp4AK0wieGFMSe4xdZTxJ9bGW
         MU4qI61L6nNc+JCkOSUuD1mabor+BrwZgXVs4SKqiSzhgACTsqO76N2/N+TDCvsEb7ES
         DUitOj8ArzFv8Yi25qSOdjPMZq7T0/Jpd0oofHQHPjW6dP6qc5ycMfOg10WWOE+BFIry
         XVP3RsyG6aohNZiNdRx69IjKYGyzVuP93RbcampIQROGRNrVWrURwjGjD41p41VjWabT
         zxDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SFkIMGfej++tW1fm34B9oovKy0y64yFd7oFw0n4CneU=;
        b=kg2f61wochYKIEIFbm5CudJv2US2ih5H44LzmxxQ2Wyvxegan0XX8ZNBvievpzGXT9
         M57+plbex5agW2uLsij1UWU3zhSRwbD3a08GHvSmYYsOgjjf/+rsdbkVYzI7aGkB1p1s
         /uWX/Hwt2njqQYcsQrSSUifvjBUfto5KecOrrwBAVZBFxc/BGMSFVP/pG34KHOd1SC1b
         PLuWCf8fzFUK9rlhEF7Cx6StX79jXkYn91WRQMpAlz2QIjaXbzagLtTxV+pFC1daZ0SB
         kFBVTECGnv/AAFiXCv0Cb0Gq2sME+2TrY2Z3aWlDisMDNz5XHbMaEu29a8/vK9Swp33c
         OV8g==
X-Gm-Message-State: APjAAAUVOCJlIo3DArhRt22Ffd7WMsaTd7ffb1tDC+rCZhaVvmQmWtEy
	XEStg49irntDu2RMBG7umX0=
X-Google-Smtp-Source: APXvYqye1kJhDdaGIComed36UwsD/n36A8zWsxHIIyPo0zG1TIAmHkKcTBia0rbuqX+fxknXjEJsmA==
X-Received: by 2002:a17:902:7043:: with SMTP id h3mr6062210plt.10.1561559284173;
        Wed, 26 Jun 2019 07:28:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:22cd:: with SMTP id s71ls2087177pjc.1.gmail; Wed, 26
 Jun 2019 07:28:03 -0700 (PDT)
X-Received: by 2002:a17:902:1c9:: with SMTP id b67mr5895448plb.333.1561559283800;
        Wed, 26 Jun 2019 07:28:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559283; cv=none;
        d=google.com; s=arc-20160816;
        b=jf/2U5jQhGSkCPBahUry/AxXLPaHVuEourlpFiMv9wEOU1lmCZtgPN7RtPOFEejv4a
         WnLo0iDqfOXIuSNdRldAi6SduaVmZ/A3KQRI1+d4ndo0Exv92vdxwsBw0ZChMutbx83j
         Ef87jmxw0S5AFbUt4bzlzvV8Xw+fmTKMqN+RZUJbjsWaP5+FlvM5xVjlcjnsEUpuwNfy
         tlpHx+ls83W74T4rglocDJMKzaPFvjsrbcI/lwdUsJ8hmA1wWr4uV41q/Qao47lfDWoc
         L5QxB1ltIYGF3YAIbQOvNXfolgxVm7oC2gSN+3RrsEN0TyVEKSnDgnhJQZAXiJHh77LJ
         m3Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/Bjb3ErsQTLw+YrlSLkjBcr6K+fvu3f9fORDBwR/vbU=;
        b=EI9kctSfYjk+2oDtwP0dR+gJy3NeQqPulx5wX4WGRitKZPILxqUa/nCdelICS8Oiqd
         RDlOP4EB94UkbyHrzTizmTgVn7f7opEodfJ6tJLGBISIv2A4QWF1M4dWl2gaNwNQvWDA
         Xdb63uBX4auJTlF5tn9VBkZlotR/Jq+uyEyS4hoNBeKmtpdlu+HXW69b2N+gqvexsGVO
         5MrdQl0GQ/9ZQtkofF4AKiWa6aWop+lHEBReCvvC7g63KZJuPXZYvJRXG/tyS5SslYvZ
         gED88c3ZsqvRxkyvWY0vWWsVZbJhNIImLqAJx0SPCw4jdL1b78FKlo7F75O16+SFIehs
         zLdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gU068bo8;
       spf=pass (google.com: domain of 38oatxqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=38oATXQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe49.google.com (mail-vs1-xe49.google.com. [2607:f8b0:4864:20::e49])
        by gmr-mx.google.com with ESMTPS id l3si36471pjq.2.2019.06.26.07.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:28:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38oatxqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e49 as permitted sender) client-ip=2607:f8b0:4864:20::e49;
Received: by mail-vs1-xe49.google.com with SMTP id j186so526344vsc.11
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:28:03 -0700 (PDT)
X-Received: by 2002:ac5:c2d2:: with SMTP id i18mr1273686vkk.36.1561559282687;
 Wed, 26 Jun 2019 07:28:02 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:12 +0200
In-Reply-To: <20190626142014.141844-1-elver@google.com>
Message-Id: <20190626142014.141844-4-elver@google.com>
Mime-Version: 1.0
References: <20190626142014.141844-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 3/5] lib/test_kasan: Add test for double-kzfree detection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gU068bo8;       spf=pass
 (google.com: domain of 38oatxqukcteryiretbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e49 as permitted sender) smtp.mailfrom=38oATXQUKCTERYiReTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--elver.bounces.google.com;
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

Adds a simple test that checks if double-kzfree is being detected
correctly.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 lib/test_kasan.c | 17 +++++++++++++++++
 1 file changed, 17 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3c593c38eff..dda5da9f5bd4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -619,6 +619,22 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kmalloc_double_kzfree(void)
+{
+	char *ptr;
+	size_t size = 16;
+
+	pr_info("double-free (kzfree)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	kzfree(ptr);
+	kzfree(ptr);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -660,6 +676,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kmalloc_double_kzfree();
 
 	kasan_restore_multi_shot(multishot);
 
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-4-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
