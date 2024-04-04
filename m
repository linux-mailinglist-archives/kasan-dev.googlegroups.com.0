Return-Path: <kasan-dev+bncBCXO5E6EQQFBBPOBXKYAMGQELXY4XIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A9B41898824
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 14:44:47 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7cf265b30e2sf99628539f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 05:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712234686; cv=pass;
        d=google.com; s=arc-20160816;
        b=qjBEB0jsNDphoa0pqWeEcKbKzy/pfFxI1QavwGZsTpZ9+snbDJnp1Poyjgmj1RVp6M
         2BcXOD2suUtF/aT/dKVWyiHJn9C9L15u/mGcw5xGdsX16l15Eev3px7mQtfli5fnamh2
         YqoOOR5M9IXHEgTRy/2fUFogdaP1bobbCyhbmjnAD7t/DrRC8SXVTIW1rhS92xCkVisF
         zmGnRWqpljV58ejwUfbtU7R9VlehaY+LYUAw/m1tLNVLXhkusR2olc7cKG1pvG+v7QRY
         KmqUcjJu8q4UfCkRz1fp+OBb8OWCYG0lKENULeAV9YW7ROrarlNybMD+cZ5H/0PR9k5l
         CIoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=s3bCsgWCrmyAiO7atch+t5GygQYH+wsq0c+gx7tC4II=;
        fh=ow8qtBzov/3Y6Nqowl+iRjotVP9QR/mfSbB4t40fn+o=;
        b=Jd6Ibpyw97UyBOqS0rc2BGh8+94RApgpA3I2LSFwEsw7lHrcGGaHhLZK3dtE7jwj+L
         1awZ3rgUgulLA7eOzrVxJklxZEse2sj5P178ircDnkS8ioKYZFz4A7oheS67Jq7U+C59
         DvDFZICnQOJhuFuCUaRw7sgn252PKWLak7m9BXzX541qCoQw3aOoFRIpOiY+5Hq8GpRk
         WGyq5WAMglTAbKYrbNr+UcEdGSTs3FLvqIcjHhJreKXuMcDPszgUuJeujbGXry55llpK
         b+DLuwLLj+OsnaiJ8Hki4nIxI9QR2WIzOnoKBJb4M5z4BtFc3CQ1GD9jiW79jxGP2knW
         cm/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JtcneFIy;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712234686; x=1712839486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s3bCsgWCrmyAiO7atch+t5GygQYH+wsq0c+gx7tC4II=;
        b=OeV9hcIrjZmDz0oHjdaMW/rWK9HKNnKdvDugKGs0VHVy89bAVClIVjBKmtwka+mE2J
         AayKh7IMSlUAeXE1tQb4DPitdqwOWLQmRcxgqMMFfd8/ZoN80NfGIebp1kUx2/ymgiEr
         CNR8Y8frNLBMrskXFgghpYSW9/kcaFzAUm+coKdxR1D7EOU76rzp+CEFVhU9rxzLK/YP
         YuhCdBQixZOpSd7Tgg/CO2NwYpMjjvU+eTqeMwOG71ZzIvCNCCexaD0gUEPlJRJxK2ub
         2swvCwx7n0xZ6EAFSDwKIujPvLkun8M6tlnFCK/ti09QYWVeyz9nMG4AKLmA+0BVpgVb
         +fHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712234686; x=1712839486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s3bCsgWCrmyAiO7atch+t5GygQYH+wsq0c+gx7tC4II=;
        b=d7+7guSuzLRZUVFR5qhvaC+wceLLPEyAttFvpZAvoPL6K0l9DG4uZzK6EshLetxXI6
         a/I6ktkCvsDH2aA76pokNwmzkAja61I1tq3kZKd5s1bvZAVwkya3mCy4/I6evJVe9mpD
         hgcsXFcstA4G/u6MBgQ57MVEhq4F1Ymw/LF+ZAy8gDeYa7PGTffgg2wTGuYcJdbR5YiN
         k9b1U0tRvuXvPFRchySqd4nNnytvhF2SAweXSWWyJmHjMXL5xq6FSpWUaS0+W3os9TGf
         AqSec+kJtUaIHoYbd9FJEHYulBYQe+iTz//MP3A+FewiRkf2atXWnYYIWJofknW5QggO
         +eTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHET2aluXuSGb+Cc5tmnuNMQaTENTMC4/Ph78yzJsgXMI7k/Rsvs3c282XkE9ggQF9Zb9P/SXp20oC7lFzOb3ny22i7yHz/A==
X-Gm-Message-State: AOJu0YxCzbcog5Q1zjqjVU/2BWSx7P0roDHvXNm3lZAHIoefqUjkcVzE
	50+rRvODCTxv7HvcxY4jATZg7RGPt01zU/nkinQuQtE23qVpQra9
X-Google-Smtp-Source: AGHT+IEIS34nq9nIYbEXxNOlynrwzkArWi+rlAybJMnBGz59sirngTzSAZ03BOGBUdfSj6hlFiL/qg==
X-Received: by 2002:a05:6e02:b48:b0:368:ba11:5395 with SMTP id f8-20020a056e020b4800b00368ba115395mr2599176ilu.14.1712234685415;
        Thu, 04 Apr 2024 05:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c249:0:b0:368:a702:92ec with SMTP id k9-20020a92c249000000b00368a70292ecls176759ilo.2.-pod-prod-02-us;
 Thu, 04 Apr 2024 05:44:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxOLBwVcVG2AO2EZ49jfpP7+J9UmMTpN1uSKnSf6AMreaO3AHTqU2azNBArix5R6MPmVd6NvrCO9TUpKawEp2dTkIw6bfclCdtyA==
X-Received: by 2002:a05:6602:5c2:b0:7d3:56a2:f32c with SMTP id w2-20020a05660205c200b007d356a2f32cmr793303iox.7.1712234684445;
        Thu, 04 Apr 2024 05:44:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712234684; cv=none;
        d=google.com; s=arc-20160816;
        b=BluWmC/WHLlacKeK3BWB0DVVqd6icQyaKtCEZCdEBx0lAX5Bsc0YyWFI8FHrBLYP/j
         xOILnnTgj0y7RdDLgc2+QUNtF/avWmpTm/LSuuoW6+Qe0EyvDxEaadfcNur5Set5zI6x
         f2nOK8Q28KQ/lMBAxMcjxFnlNQ63gIHyNqK8KKL9JmIhWXTlO5dy7mhcA26D7JOLGhta
         4LVnxrcPNqA+5HaSn/mXakWaOPzQJyrny1MledOoLWB926gC/E2uOMTCYPaZ/NBfDhM0
         P8dqfLiVRqfA3qx8r/yFW+qrRbh5Qt9PG2z7Jk/VGvrPHLtwNVlH6uSbIwKNzWQKtmOi
         bgpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=06QqaCBJF0Jc/qXKHLuR5jaL/IXhGPXW7F0jaiCDW0M=;
        fh=69h9oclji40l3unNYFJNR5oTvTbhJaQz4t5l7NVAZ24=;
        b=cL0DP0VNSJTO+vwpIP3ERHgMu5DoEHBT6pOqG6NijnwikxwavexfjC8B4C3TS1m8xr
         sea+afUzzVCQlzwVmYf/FTts+4IgQYDNZm1lCLKApwieIrgIaVUkK0IP1n12ubDgdfRf
         HPev/sx3/UFLpwV6F4/oB+QZ0F7ueJc7epGoo7RD5YbnEcNxKUrdWbO99pIlxv5KQpRh
         eWb8kXzgqcKZwX0DNoU7V7a4b6pSoUnooOSXhsJI5hHJk7zIrFrT2wU3cIa4kUOz0Z+5
         XSH/7kcCv/WMVIZtXdWYz3AWMgdZcWzA2FgipXGDk5Si/aF3fyums8kL0TIKxsL9Yvj7
         VuFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JtcneFIy;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id ha15-20020a0566386b8f00b00476de528316si1215007jab.1.2024.04.04.05.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 05:44:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id A269DCE2DFB;
	Thu,  4 Apr 2024 12:44:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 82830C433F1;
	Thu,  4 Apr 2024 12:44:38 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: hw_tags: include linux/vmalloc.h
Date: Thu,  4 Apr 2024 14:44:30 +0200
Message-Id: <20240404124435.3121534-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JtcneFIy;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

This header is no longer included implicitly and instead needs to be
pulled in directly:

mm/kasan/hw_tags.c: In function 'unpoison_vmalloc_pages':
mm/kasan/hw_tags.c:280:16: error: implicit declaration of function 'find_vm_area'; did you mean 'find_vma_prev'? [-Werror=implicit-function-declaration]
  280 |         area = find_vm_area((void *)addr);
      |                ^~~~~~~~~~~~
      |                find_vma_prev
mm/kasan/hw_tags.c:280:14: error: assignment to 'struct vm_struct *' from 'int' makes pointer from integer without a cast [-Werror=int-conversion]
  280 |         area = find_vm_area((void *)addr);
      |              ^
mm/kasan/hw_tags.c:284:29: error: invalid use of undefined type 'struct vm_struct'
  284 |         for (i = 0; i < area->nr_pages; i++) {
      |                             ^~
mm/kasan/hw_tags.c:285:41: error: invalid use of undefined type 'struct vm_struct'
  285 |                 struct page *page = area->pages[i];
      |                                         ^~

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/hw_tags.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2b994092a2d4..9958ebc15d38 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -16,6 +16,7 @@
 #include <linux/static_key.h>
 #include <linux/string.h>
 #include <linux/types.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240404124435.3121534-1-arnd%40kernel.org.
