Return-Path: <kasan-dev+bncBDGPTM5BQUDRB5GVUPZQKGQEAP4NJ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F9F181A0C
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 14:43:18 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id d9sf1101070pjs.2
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Mar 2020 06:43:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583934197; cv=pass;
        d=google.com; s=arc-20160816;
        b=vSzeI4Xze8bxdLqfLtL79MnUqsoF/4QRduk2FvGIbrCD84Mf9d2L29KaxngO4t/Pc/
         FNbnPYZ83nzXLDIBT4H+XxoLn0uXUH8Hpyr9h5kBuLu/a3GFF0eFgPa+W+AM1OHZjK8q
         SYrAuYr/TRcnGb6oJoLJeUW3pczNqc7Qf0HPemRy3ED9TUYb7oNFFntuH9TSjlcREyop
         7xxdMwtH7zL9lO1bxcMuGbyoPVevWcQJPNv6ScOoDh+/iq/ZJ9ZtmZuuvjwXrFaCY810
         WbSbmjL41OcPRoRKi2MGEBh0rf6ekkDwttsQQrJbRPDw8/5JRLXDxcUexZ8JfzZ9eG8U
         Iqsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hWTTza2yn8KpU2VKh7tVn6wEtCwxFJ+ZC+o8QRW0biY=;
        b=kXRhLp3kk1pHymwA7pjKd+JCwUzgvVGDCEN/eAbdp9+o5nd6U7IbNPe68ZAoI3lq2V
         sg42s+elyubCGkLpHExVGZSEFv3rzSODbnOmfsZNnwWe2RK6eCZuLbisB5iDiVbGTnV1
         i2kDw8Tcf9NXKL7T4SHROhqjOuNrFY3DOHL82Ois2pHcnmcGlZ6/Bz1PUMnJBJ6d3PGd
         tW0f7uEyw6n2zAfbueTTZ+l1pJGasYj4jU0XDQbv5CdxvsN5wK8FtsfO5r76vIN2UTdp
         p7Qrhfywl6ZBi5izCNn0eRbFvrN8tOajVYQDneSAuVzlhv/rOpqrS87oIZVMlm4KS1T/
         ylBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="idwf/PwL";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hWTTza2yn8KpU2VKh7tVn6wEtCwxFJ+ZC+o8QRW0biY=;
        b=oV8deTHEHPVQeNMWxNP/4xYRIMP1zOldZbvA0UCf5hyy+7hosMnbLt6qweRzDh8Osa
         fXHf6BBIhJsR0xaEJ851hwzDRTbDnkJ6ijBQzQ0XZivT5si9Kjln8Ga0KQ+VkI+Ty+sR
         L4UELhefayO/MSx5UGLENb8skg2ZwT2gOtVb+3c3o13EX3EgvsaFLsuftAUP1PRoZ+82
         KLWqXM3d4oGYi2EdKVb4KqOyU2LaiX28I5oed5etc4n9LnEhFtrp6DcQziSP0b1VmnGP
         DSP7s0QXVxk9CMUS1mW9DI5dAKzYTVS9d7Uh/adTBIToGSj1Ph7Imt2CW5hhVNq9vs5/
         pgrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hWTTza2yn8KpU2VKh7tVn6wEtCwxFJ+ZC+o8QRW0biY=;
        b=ERDeTdnraoBkGdB0e+gJZ/cPlcP7caOxneJ32SSyTbWwOswEnTMssIvDQ3AxMDw4+2
         TWz961acpX/t6yZfDnuxsNk205fzt44L5RXJuo3QvA82dJpOXK3MkW/pEF2cfzyIuoki
         sDpCPoyTjIiLRmcv7FiN9GGcq50BOqFyuKZCpDEmgjD0XkQu4UoGJemzqty2izuQXPyM
         qIzsJIy742VmLnxaVf+RwSY/6R/lWh9Rg8Qg5vYhjvame5YqI2Bz3OS94kBKWvOV+xwL
         cH/bPOD69Bb6Vk6nkYngEL7dlG4E3DFem/3fmCW13jq7SM9gxHCuqVASo02ceO/hDHry
         XYOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ34C0tjp6wSGDGXjVk5qTP8SK503VQLWxZzDiq/4lXdPcj7Iqse
	Mr807JzAhWEKmZb91CCZyDs=
X-Google-Smtp-Source: ADFU+vvJEE70/12xBstaebDPV2OU5yaFEja9LktRWIuObkFsdOWvPQ9zl7P/oUsYAm9SgVObJxeAYQ==
X-Received: by 2002:a17:902:8341:: with SMTP id z1mr3124871pln.178.1583934196912;
        Wed, 11 Mar 2020 06:43:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab86:: with SMTP id f6ls975548plr.10.gmail; Wed, 11
 Mar 2020 06:43:16 -0700 (PDT)
X-Received: by 2002:a17:90a:9408:: with SMTP id r8mr3591760pjo.15.1583934196512;
        Wed, 11 Mar 2020 06:43:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583934196; cv=none;
        d=google.com; s=arc-20160816;
        b=OjXs/eE/R380vAcuGcciBTWxophLEsaT5gv+cZ2woqdRdQ9nPXQvUmNuvJKnaEc8wF
         V7uwu5JwOHrHLpHr8wtZzMsZz3aYYZm94+Mk/tNKqdza/h3Gtxpk6InwWBa60dXUrzTT
         2DbFwr3Avnq9gxM5kMcMb80sxka83yS2wdy/yXqFFq4ftRZ++0q0m+SQxpDmOKPIStw5
         86EuGTvuRCafOOch4cknfLdh09hPWaQ3DPR34nIKph5y7BfyN4xZME+jpX8/2OjMC1C4
         qO+Byz0StrbG+4Iayyt3JVULNrBhvxWhrENHl5oigEiNbEEUgnkslpA7Wckv6dMTzZN4
         Z9lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=A72jYG29ZYGID3peLueFYfZ09ab4hxkJOXi8FenC89M=;
        b=LvXfHU1y52iLKSmkYhiJEpe5TPqNTiQCEd8RY3rPdO89fOZtNtEBbDyn1z/c0Aqe0V
         WymCq2nty9NmwrcT5W9m8qTbPJxBXgXJe2a7/jpqW1X2DbozbL0zQWxb+nYliwjU3cQA
         I/eeFwcwhEWncTvCIRFQC6eKL3/WzU71AWE4HQetR/D2vFIm9T/XEL2OT9fYbBzvE1gv
         V5vlnn3z5YmA3KjBMH+6AYVmjXODNStfmyCAiYwIUmEKhCvNbIIBDPDSVwsJrfw1frTm
         OYK6qwNiv5vHK3R80Q2j7DFIuUrstGF40VL3uPDInAEP91560X8k8nWa10HBL8QpT6FS
         WWgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="idwf/PwL";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id y13si67603plp.0.2020.03.11.06.43.16
        for <kasan-dev@googlegroups.com>;
        Wed, 11 Mar 2020 06:43:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 4ccf4a7c67bc4639b58278874f1ba63b-20200311
X-UUID: 4ccf4a7c67bc4639b58278874f1ba63b-20200311
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1806468321; Wed, 11 Mar 2020 21:43:12 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 11 Mar 2020 21:42:13 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 11 Mar 2020 21:43:18 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Qian Cai
	<cai@lca.pw>, Andrew Morton <akpm@linux-foundation.org>, Stephen Rothwell
	<sfr@canb.auug.org.au>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH -next] kasan: fix -Wstringop-overflow warning
Date: Wed, 11 Mar 2020 21:42:44 +0800
Message-ID: <20200311134244.13016-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="idwf/PwL";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Compiling with gcc-9.2.1 points out below warnings.

In function 'memmove',
    inlined from 'kmalloc_memmove_invalid_size' at lib/test_kasan.c:301:2:
include/linux/string.h:441:9: warning: '__builtin_memmove' specified
bound 18446744073709551614 exceeds maximum object size
9223372036854775807 [-Wstringop-overflow=]

Why generate this warnings?
Because our test function deliberately pass a negative number in memmove(),
so we need to make it "volatile" so that compiler doesn't see it.

Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Qian Cai <cai@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 lib/test_kasan.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index f123b4b8aadf..e3087d90e00d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -289,6 +289,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
 {
 	char *ptr;
 	size_t size = 64;
+	volatile size_t invalid_size = -2;
 
 	pr_info("invalid size in memmove\n");
 	ptr = kmalloc(size, GFP_KERNEL);
@@ -298,7 +299,7 @@ static noinline void __init kmalloc_memmove_invalid_size(void)
 	}
 
 	memset((char *)ptr, 0, 64);
-	memmove((char *)ptr, (char *)ptr + 4, -2);
+	memmove((char *)ptr, (char *)ptr + 4, invalid_size);
 	kfree(ptr);
 }
 
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200311134244.13016-1-walter-zh.wu%40mediatek.com.
