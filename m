Return-Path: <kasan-dev+bncBCKPFB7SXUERB3NQUTEQMGQESKD3SWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id B2FB5C90C57
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:35:11 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-435a04dace1sf11895955ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:35:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300910; cv=pass;
        d=google.com; s=arc-20240605;
        b=d8JUw6ltPz6sc2RWM67YhixaxMvhVe7CnwyFRXG9h+3AW6DHw09CnlKEAWx0MRdSCa
         mhg2Ph37mOe2FVewAEKjlV2lfQkDCAIwFqKThnPQGzBCHOrzC61wmJGajCmXFNSgYGEO
         QKMMwCwJwrVRoCINIRcBeFKx3VkZ+AWPTYZjtg/TtWvdqeKEw7ozH/uNN6hdaRN7vc02
         8CKH9rL3BaIwa0i7qW69jevAs+C4I1dn3Wzmg09DZTqA/HH/MAzfP3G6nbVW/FbC4u3E
         SZgJF4fswLzYJoaSlP85vBpBH8haETfYsb/RXudNkV4lFeGuvRvbeTOoY/kDX1bTFHj8
         CwBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+PAXwvEGh7w+jGh6YOd8gh+kOf7gEa313FPp0NUKkNI=;
        fh=4mIMVda29ohwYgxNW06tPsReXd2/O7wLbq7uPfZsKlo=;
        b=FBTxw4C8/c4vr1a96n8A0T5sg6Wh0TANEIux/Wk9axMzVoU94ZcKAbd/FTJS6Zga6Y
         eGkWVpJx/gBxp0EL1UhbBwLNdlMmD+MAOp/Ghn4x7bthCSIvd9GV6vEJ6hV+vr226KF3
         NzO4HQ9u+FA1/GOxwEvJnTrQy7rl6svnNNWbAAPS+yVxLVTIAi4fhrgj1KoI7ESImd7c
         DhFpMkbfVfz2u/cr3XMvseOC5PZ4dS1cugxfVKfmx4J5/vWepjJsqJ7GCgHm+FsjAzYx
         TWpTCCZr2+FltLF5+T4nJYEqqqXPenllVMs2NapG4BVSKedA0MfMoqyLs1Um0H9R9CjH
         a1oQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hjAx16SL;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300910; x=1764905710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+PAXwvEGh7w+jGh6YOd8gh+kOf7gEa313FPp0NUKkNI=;
        b=ACx/PxOLDZaSZqd/daF/maZ+7dsOb/22FzsirPwhxGsQXx0PLq8dyb453EZz8tXb8+
         VE6WMJ9EM9EMoKcUmrOzrDf1ArY+vFSNmzyU1mKFgX5BBCqVQ/Tj3t5YHqal3DaSTGiU
         27O16x1Kbiz9hwlfrdZ08HgelsI6n2tyJH/x2Al92eauYHY22VT8PKIE7lov8LDAaxMr
         sWIO3HDQXeupPnH01y57eHePiaAeeU2UMGKjndR0vDlq5ixy+XtZKccWPBILH10gpEEn
         nZuPjqeAhCGFJiSYIe6clNCxOT68ySBynNIdbfotEG6kmaBh5ODLQyIuqNj5VeitCWGO
         HTJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300910; x=1764905710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+PAXwvEGh7w+jGh6YOd8gh+kOf7gEa313FPp0NUKkNI=;
        b=MUtKDzefaRgWr9iPa3MgPF0fq21BXS68BxOfX7EJhOVOsAmbrY9bbdd3sUAJ7orRfq
         Fa/BY4yfXXOhZ47P/KEdARGwwvrpbNFCShTwgglN9DmsG0cxwqGoD991Pnn7lsu23w48
         popnsillL65YmGgOVTHjuSwFcUQjwA6d3KCQTR6bVK+2mFa6JjzDLx7Ia8h5w/K8BmH0
         QtAs0nJxKjJg0bfw0KtAbKZV0DYQGhy6iVw4t2xhePs3sJ/wxoUySbOe9yHIdaxsn+oq
         TKQKXi9919pl9aPEhoFU9ZAWac3iXVRmzV7ckv6IK6vJgqlcXR7t44iNu62Y70d89VBh
         NxPw==
X-Forwarded-Encrypted: i=2; AJvYcCVoefWQaA98i9k8MRuoLhRsB1NL4izM5LaQ2BQw6iHAZmjJ/qXtOhcUXmDHswAYbgs8MvySOQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMQWHeCipUFpOZEsxa/rU2Xp9xie7m3i5Jqv+wV/pI1kKEr+cd
	FB+QAjXo3EzIsFEwQdu4vvPhE1EbdGun3b43Nc/gaOKcJ1vfDpiWmiyA
X-Google-Smtp-Source: AGHT+IECOFvwFhk9BGR/hy+NpF6vyt2HAXCzLlNhSt9xLznnnCeI1nvV6GxTGDOYhdGW39vCY0CBZQ==
X-Received: by 2002:a05:6e02:174a:b0:434:8ec2:9a69 with SMTP id e9e14a558f8ab-435b98c6d20mr179469045ab.19.1764300910088;
        Thu, 27 Nov 2025 19:35:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZSafOw3YjWd5vJA5cSn5kBdhFwaFfTMQw+Uuy3BZ7Ubw=="
Received: by 2002:a05:6e02:1a02:b0:433:7ab2:fb7b with SMTP id
 e9e14a558f8ab-435ed3f1835ls7743515ab.0.-pod-prod-05-us; Thu, 27 Nov 2025
 19:35:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW2xNod1hMQC/4vfgdwZfaIdXsLP5VXLYohdKydKTwg13LyF3ERSX+CfeyUXMC2DK+WdJgiUL7akdA=@googlegroups.com
X-Received: by 2002:a05:6638:3172:b0:5b7:d710:661f with SMTP id 8926c6da1cb9f-5b967acd806mr16054620173.22.1764300909031;
        Thu, 27 Nov 2025 19:35:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300909; cv=none;
        d=google.com; s=arc-20240605;
        b=d2resCTIuldmh0HDj9iduA9gnozrVgUiN2hDMgzSbAWZWuUdTndvQvQn1apvrc3rYL
         jMYdnk0gReHQvDaTz5kRkBMJpdSi1+RAeeGlcQJcw6AeX0PRxnrSQtxq4hdRxEzspWe3
         4+MNwfcG0NGTF3tCI2ZIy1eY6px8MtOltwhTFJlng5bo+sBF724QgxoQWkK1yJZLt4ir
         kQkljp9CR0JLQSDvKMAxAe3IanbzEI530b0l8iGFiAzT8A5GM22w+ectpakjO+B/PREQ
         kb8BcvLGq1jaEQuZVbMgxLcPavNA5lu/4ccT3CyjL5TaAxCI46Sxqr3iQiuA/DTGxTlF
         0kYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vYIdm7jlXobjspOXdxZmqxS4c3i3lPHjIs91tkUv/to=;
        fh=2a+qDqimSEVqrId4x4klml69GAR2OA7IyOuw7Tqpi5I=;
        b=GPVO+2dKWq3SCFuqVo04LXLS+COMQ1uLMd4IN26mst9kElW6CtcKhU3syeyNKFBoEa
         VfoGj2rGle95XtXbNddXnXkuztP+2KCG8JKB7y9u37x1Z8DHWEAf1YhfkSstYVjY4xgG
         OTx85imAD7inZA+HQyjHUWOJWKr5cIrth6yky4kc99pNymjPWaQs5TPli/Vb4U1esasC
         bxML3ua/0bLZZ/mAMPr2ClrTUk/kIUZygZ34droRC+XIzJvTFIQLDOs94q0Y8ouJ/TWl
         6lxl+IqUyFHIaQf/sXz5tt2CDULre6dD0popBUzJmnjy4LCrEfynX//d1Ss0vH4TM5jw
         nWLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hjAx16SL;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5b9bc828d04si69887173.8.2025.11.27.19.35.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:35:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-486-iBrk60d6NraI_aoxKGyGxA-1; Thu,
 27 Nov 2025 22:35:01 -0500
X-MC-Unique: iBrk60d6NraI_aoxKGyGxA-1
X-Mimecast-MFC-AGG-ID: iBrk60d6NraI_aoxKGyGxA_1764300899
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A3AB21800250;
	Fri, 28 Nov 2025 03:34:59 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id BEE9219560B0;
	Fri, 28 Nov 2025 03:34:51 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	Chris Zankel <chris@zankel.net>,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH v4 10/12] arch/xtensa: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:18 +0800
Message-ID: <20251128033320.1349620-11-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hjAx16SL;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

Here call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: Chris Zankel <chris@zankel.net>
Cc: Max Filippov <jcmvbkbc@gmail.com>
---
 arch/xtensa/kernel/setup.c  | 1 +
 arch/xtensa/mm/kasan_init.c | 3 +++
 2 files changed, 4 insertions(+)

diff --git a/arch/xtensa/kernel/setup.c b/arch/xtensa/kernel/setup.c
index f72e280363be..aabeb23f41fa 100644
--- a/arch/xtensa/kernel/setup.c
+++ b/arch/xtensa/kernel/setup.c
@@ -352,6 +352,7 @@ void __init setup_arch(char **cmdline_p)
 	mem_reserve(__pa(_SecondaryResetVector_text_start),
 		    __pa(_SecondaryResetVector_text_end));
 #endif
+	jump_label_init();
 	parse_early_param();
 	bootmem_init();
 	kasan_init();
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index 0524b9ed5e63..a78a85da1f0d 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -70,6 +70,9 @@ void __init kasan_init(void)
 {
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_START -
 		     (KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT));
 	BUILD_BUG_ON(VMALLOC_START < KASAN_START_VADDR);
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-11-bhe%40redhat.com.
