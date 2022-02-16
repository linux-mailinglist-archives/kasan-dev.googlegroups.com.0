Return-Path: <kasan-dev+bncBAABBFMUWWIAMGQEVGLUUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F8DE4B90DA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 20:01:42 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id v13-20020ac2592d000000b004435f5315dbsf1004089lfi.21
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 11:01:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645038102; cv=pass;
        d=google.com; s=arc-20160816;
        b=sv78b1jwwAsDLZo1eHSR8mAKuPAYOQNPspHbYXoSNsvtIukvvFVmxUyWyppjN5zQEY
         uxNL9uqWY2g2piwulaJXVzqE18y+3drbugHJobvNYzZ/SVfV0YqqtsN54QiD7eZt5xSO
         20nnuD1QktRe6F4RhnXRLzxTbmibweNJO3EzelRoxq0e4X/I68KL3gVfKYGsJ25QRO8s
         s+YS42wNPrCRdBLA1v+kVbM03nUCROMX21R03qNf0axyaEHkgEOpw4XP/TWFhiqTquxz
         r8TOBt+o3vKd8SRJLjYkj80EZfKap4XQ74f6xzvwLD0snWZ5oUu4SWTNED7ue+DjNFDf
         7FDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=w8VixSf/hRX/REpPKcTkLKgxf/V8MBdGxkenwkEDK6o=;
        b=kZDOdUsDO3KxfT7IfQ2F2LM6WufCXChNLk44Rb0rwkr0O+xgzuftjQqZseGo4YXdUH
         j4atMBTOFiXL+wN1wpQfrnlBTVKr1Ko8J6AIjPlggZnfcfaeN1dkkndPpuxbCpVCjLul
         LOi/MybT72Z/oLA9eoevhg0J3B6T0vz1T/PfNYdtxEeDRkakJA3nE+G+UgxrpahiatXR
         Lcw60nYzPX0KNHyHE0fndQRtHLeAgZVT7K7yqd+fGlyJghksa8TBwBL1cwHfq7/eL18X
         G23RW7u3iz1nwJHMR18SLQyV+6tOLzEk8irYPT+BcXCQECytJ9ABfYFR1oCBhLNGqs6o
         ejFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cCAtLRxW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8VixSf/hRX/REpPKcTkLKgxf/V8MBdGxkenwkEDK6o=;
        b=XHsXmDwEbi7gWRsLYiQEamxkW7Xt1lN5zg5v4YvgNMIytVm3MzxlFaN+VQpohTVvpd
         UWFnmRpz5aV67xEiacmLCywB2XfXjDk3gXiEZ4FBOacwcf7MDoWlcVRNH4zM0C9HDPyz
         DYhERoetzSKyqE6UaU9K0mFDJ12PFxdYt9H//g+cUGXInXqkNy9JpRAYq/9VXjR2pApX
         zm5QclGvR/qrimJQ2kLTwHXkIgcjV4rnE21D3IFSZ+qSvZys822rSQcp/N0RnEK1X2E1
         sxHHG/5QzMs3BxhMfjIRIYRQGFkr7ktiX0I5bTT+zuwnZLC9HwUiAbV+ap3JFU/EgAT8
         YpSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w8VixSf/hRX/REpPKcTkLKgxf/V8MBdGxkenwkEDK6o=;
        b=XJyCjlhBHSmjgZVkUvIffrrj5guDHlAHWtZ5h2Nn9VlIHhdOeGtQj3Clwe9rmDgpiE
         lNb2CQovgH+7LLbYdtrmzgyEBVwLWjX36hZyFix5SsuXAD5Rn9+gj6q52936t8zEUyfZ
         IS9jAS2AQqfuGiJPAcLmqhdWvQAsziE1GCioeRf3Q92b7qYvxFgLqSNi28bRuW+3g0lH
         v/bCuhC/bS8dcDp6O5+1WT/hZIl8/oFffvtYW0kebBBbf5iBr707INtXjgvk0SxLa5ms
         XqPKt7hp1KbdPMFrnFI77OIdKoDj1aY5E71glz/FwSetWlhgv8cHA4FuIN4XYGYgzNf/
         6UXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531KhS6IntNocQrVxYjLF5sXpq3r2frVX8QpX0n6aOKzlNSaOoVF
	C2coC54C4+XbMnlcoqjooOU=
X-Google-Smtp-Source: ABdhPJy0Cg1XTbzBaJgbKuuAFiFrHJkqw1CrCnS8TcvX9ts6ddapm0ujQHJOwobam5mLcFwzbYo/cg==
X-Received: by 2002:a2e:90cb:0:b0:22e:5363:95f0 with SMTP id o11-20020a2e90cb000000b0022e536395f0mr3158360ljg.210.1645038101963;
        Wed, 16 Feb 2022 11:01:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b8d2:0:b0:241:879:3666 with SMTP id s18-20020a2eb8d2000000b0024108793666ls128732ljp.7.gmail;
 Wed, 16 Feb 2022 11:01:41 -0800 (PST)
X-Received: by 2002:a2e:a786:0:b0:244:9147:a876 with SMTP id c6-20020a2ea786000000b002449147a876mr3049856ljf.357.1645038101142;
        Wed, 16 Feb 2022 11:01:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645038101; cv=none;
        d=google.com; s=arc-20160816;
        b=lZfpO+qJUwx8ldHBzC7C9o7i+HaZzuCbu04+BJtbliW/pwQaI6CVhKdw4BA+tC8hrK
         CyIRNH9O6vuaC+LpJeKdpUXuIHBKtMEwqg3Gw3quXxdXctcYUMLjTn//Xfnc/KsV7g/X
         4dwBr+N/2hy/+DnOvPj2h++Lpq4fIFgY094W0R2csc58KH3xUKX+piPXy3vhSWrESwpv
         7fGxNoJIIOEiHhZpZH7E4KBvn+dui8bjPNEoiBUuTOKwKHBqpNzIwHO+WYO9MKr8o1rk
         aO0l4BqBUm/fsfsUM5wsGNfpAMnjlOtZ8TeZlg+tyaLgG6uTwOtO0KD2N4k79JYtcE6f
         o25g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=KdJNhqvT10fpX2TPTtNinLyaEIbw3AI3xc8h9ebWAy4=;
        b=luCxQ0axEb+2LUBpTNNGnnfX8R54dCaZtXBT54/DxciZqSpJ32/vSAp+N8To936oR6
         160jzNpujylBQuQfQajWUqTU9GiXyMNsYZSLqKPgfOHW/UlB63R7QfeLqZaQB5Cs4lVz
         XeL4S/RbLysLcbSnoK5EKNSv0JksFOsZjblgCDrS1JVNXUsZS75h9HyYKoT6YMSk/Cst
         10Ra1KaLcr7V6CbcTcmIaET/F2c1buAdqToysyI8idL7UHMclXHInbrcHus1LjhEXNJp
         B6AQovYa0qceGDNMZpRJ7ANsIiCq/pXfMnqrPBp54GT1jqA8SeJ4iZM2+8T69OFhUJkC
         xC1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cCAtLRxW;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id i5si739290ljj.4.2022.02.16.11.01.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Feb 2022 11:01:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] kasan: print virtual mapping info in reports
Date: Wed, 16 Feb 2022 20:01:37 +0100
Message-Id: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cCAtLRxW;       spf=pass
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

Print virtual mapping range and its creator in reports affecting virtual
mappings.

Also get physical page pointer for such mappings, so page information
gets printed as well.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Note: no need to merge this patch into any of the KASAN vmalloc patches
that are already in mm, better to keep it separate.
---
 mm/kasan/report.c | 12 +++++++++++-
 1 file changed, 11 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 137c2c0b09db..8002fb3c417d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -260,8 +260,18 @@ static void print_address_description(void *addr, u8 tag)
 		pr_err(" %pS\n", addr);
 	}
 
+	if (is_vmalloc_addr(addr)) {
+		struct vm_struct *va = find_vm_area(addr);
+
+		pr_err("The buggy address belongs to the virtual mapping at\n"
+		       " [%px, %px) created by:\n"
+		       " %pS\n", va->addr, va->addr + va->size, va->caller);
+
+		page = vmalloc_to_page(page);
+	}
+
 	if (page) {
-		pr_err("The buggy address belongs to the page:\n");
+		pr_err("The buggy address belongs to the physical page:\n");
 		dump_page(page, "kasan: bad access detected");
 	}
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl%40google.com.
