Return-Path: <kasan-dev+bncBDQ27FVWWUFRBSFZSLZAKGQEZTLUJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6327515B615
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:48:11 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id c16sf3686601ybi.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:48:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554890; cv=pass;
        d=google.com; s=arc-20160816;
        b=bgHJCNjUZcLn5S844Ml4hxpqItesv0Dm1/zapAW6m1nG4q/8rOyG7q/aKph4KjPEY5
         gND+7LVnjADThOZGHi0q/Fv9XA+gNzQu7FjUCN425KQQ1z4IF/IhDAktK6lK7mHRUzE2
         qSICQKN5VyxDLLOQE/t+959l9iaHi3TMJOTQA7C2csi9teGiw2tSnWCq4GtUQLCZiDH3
         qcerA/ZqCTRe0WytAAP4qXJFmuQNasEjRr4kXIBqZXBt/LQ0gwgLS9ByFgQO6cSrrG9z
         6t4asUge0zssaSV9Ho753yTVpMbCWgNk/c0Zt7en+03JvNN4SfU2xX7+o9tfzcRCYJzA
         90yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PnQPEeFlHcFMY5zU/PKKHBNkLRIC0rJ0I6PomcnsxRQ=;
        b=D7/+ykgKM0sy1YdSfVaCDjWxulAe5krYTxGvRZLitEqmPNLnzwys3VtyYAjK/xIalZ
         2gp5egh4fBT85ybHR52Gxm6y8TuWiSPnnHOWW3Br9mlYOkuimg5n33adZOlwxhDE6aN7
         k9RjWkE0sIqYvXxdI0i+M6/ftcx2ab738VeM810mO+eL8pO4r3rjOgqGS+8woCLI82z0
         8dR1V7zE+hb9D4gkvZumXEJN0Ha7GVxvfvdbAcGE5GJpY+rcvp20QizEMRACC6oWhVy+
         XdI5/3/EmXQmGFfd5T0ZyfKoc/XjSS73nX9NUoe3xVBHt9XzAUSyVjBHT0vvi3EGbVr3
         0O/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=f3+zjZPL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PnQPEeFlHcFMY5zU/PKKHBNkLRIC0rJ0I6PomcnsxRQ=;
        b=Fve3UTh2horkEIGXY2gOMVXIgxvFxhzG9uEzTqMq15UUufztT+1tpTJUKUtgKjUsAL
         3jPWC7trMqqODa9RxKEwy8rcPVuhAfmrz2PxwgOI0RmHNkhcZVQkbEyTs7/5dshUfdQV
         RknjawJ6qnVxtoAWEpkCQjPAvc8LbVaqMeFbWb315tiwSgWLeOu7xCtECNZJwpgr8kdt
         qzEdbXl+0l1cRUAgHnUZI+bEXEnh5+nNFiRKeK+1DilSt4CoLFJfFI2yxzTe6tDnNkA4
         NA6zOw24JEXHN5n5CFERHotBtQ3vhG+BLCTqvd4piTPcDijVnp8AC0buO/EAlQ70w3DU
         Cueg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PnQPEeFlHcFMY5zU/PKKHBNkLRIC0rJ0I6PomcnsxRQ=;
        b=JhS7kYvmVullhNxU2TGs3+msJfbSUGh43QA96AfkTrkxfQO4oDqe88HanT60o+1FCg
         UmOTQYD5BMRuktoWhB9eFu5SC4l5WogNQFJmJ40bOXLed+YJtznxh64cRY5b2v5YZWw/
         CtPzvoYsXk5TlRG5ZROn3McW6yJPHkeaNaX/BEY582iciUb7ziY/sBWmQK0bxPW2gRu1
         tRZuHi4UWUh2y1B9liSckqq9OjcwSpXLB/3rnDNBdFHh7qumP7mbDDZSMz7bsZ6weGXK
         AFT9BvHdqtT16bsa53KZyluPzgvRxjka8Ce47xDKpueJiiXBHwatH6MF1JKTocJmo7W+
         kumA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXNEgwrJM9dr1xXRzFecAsHl3f+YJuYWN9hEoZ/BnI6nioi+iWR
	EDax3bZqDnfYBQC+xKXn5Ng=
X-Google-Smtp-Source: APXvYqzB61v6zTpHpmMnaXKBWBf/ioOd6HkiJe6Ipcc2wqFi/oBtK5lAkLFxh0IcTRhSC1Rao0PA6g==
X-Received: by 2002:a81:b604:: with SMTP id u4mr12847902ywh.301.1581554888825;
        Wed, 12 Feb 2020 16:48:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:69c1:: with SMTP id e184ls1473293ybc.1.gmail; Wed, 12
 Feb 2020 16:48:08 -0800 (PST)
X-Received: by 2002:a25:6507:: with SMTP id z7mr988824ybb.501.1581554888448;
        Wed, 12 Feb 2020 16:48:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554888; cv=none;
        d=google.com; s=arc-20160816;
        b=P2jOirrzx4sTobHqygrjx7y5sMAfkOQCa/6rSEOCsr+PMO3SNgN5P6Grfb217Ijnmm
         i5nvbP5Ckj3dMbpeeCyCA4fvQl4k8ujDFiE1RY9g7Co0P2EL4PWnoAESpmrXNxw3x4WZ
         P0usr9fIM0T7aVMaA+GG1lvkJtRGVcNbT+faG1iv6LmDRTqPM1vUXHC+D7v81Keno+Ex
         RXTreMdcW/N27LDBuB4ioN9L9HJK54pPcROwG0IMI67Cn2vieeiOjHdI6CuUmJuY62/N
         XjLfUy1ydMIkl16dVqMBSkH+fERXOl/3X+w9nfrOzo3yKcjHRA8kmTCT1pCnPxP69v3N
         s5tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CaOpE+RnykMge29WfCqnRai8zpZuPSzzYfJQc7CCb6s=;
        b=oEQWE+t74oQMkbfgxj/x5JsxtcI+RW/bbyYwtc8CaEhn7xj064UBTANhV9t830Ldch
         Yt7QI1TnD2hw3CZki3gaFB6Ijps+dqgpB9dGfwn0gvfE3kKLrzWF7SWaoeCXNOR0npDm
         zW0kF6kApy1tFRJPmZUlzxG/ffiKNZfG5u5shmNyHn9dmN+gxFbZ0xxgWeFrfeUCyOEM
         xRRiTa7yapCQRlLGnq7YXQnBBp6FenNlICpS7bRCIDqBKXPrzp+qEnnxKU9Y4SF8X4GM
         3ylSIZt3zFHHcW9Gzo35MYjBlK5Ftes4kYN9uU9/Vuj9+3INpjBfDqHC/Z8uEOT9x3JL
         /nRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=f3+zjZPL;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id v64si33586ywa.4.2020.02.12.16.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:48:08 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id m13so1624549pjb.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:48:08 -0800 (PST)
X-Received: by 2002:a17:902:7c88:: with SMTP id y8mr11104973pll.321.1581554887611;
        Wed, 12 Feb 2020 16:48:07 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1ea-0ab5-027b-8841.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1ea:ab5:27b:8841])
        by smtp.gmail.com with ESMTPSA id q7sm297478pgk.62.2020.02.12.16.48.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 16:48:06 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 2/4] kasan: Document support on 32-bit powerpc
Date: Thu, 13 Feb 2020 11:47:50 +1100
Message-Id: <20200213004752.11019-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200213004752.11019-1-dja@axtens.net>
References: <20200213004752.11019-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=f3+zjZPL;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

KASAN is supported on 32-bit powerpc and the docs should reflect this.

Document s390 support while we're at it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Changes since v5:
 - rebase - riscv has now got support.
 - document s390 support while we're at it
 - clarify when kasan_vmalloc support is required
---
 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 17 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..012ef3d91d1f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
-riscv architectures, and tag-based KASAN is supported only for arm64.
+riscv architectures. It is also supported on 32-bit powerpc kernels. Tag-based 
+KASAN is supported only on arm64.
 
 Usage
 -----
@@ -255,7 +256,9 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently this supported on x86, s390
+and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
+with module support, where it is required.
 
 This works by hooking into vmalloc and vmap, and dynamically
 allocating real shadow memory to back the mappings.
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..26bb0e8bb18c
--- /dev/null
+++ b/Documentation/powerpc/kasan.txt
@@ -0,0 +1,12 @@
+KASAN is supported on powerpc on 32-bit only.
+
+32 bit support
+==============
+
+KASAN is supported on both hash and nohash MMUs on 32-bit.
+
+The shadow area sits at the top of the kernel virtual memory space above the
+fixmap area and occupies one eighth of the total kernel virtual memory space.
+
+Instrumentation of the vmalloc area is optional, unless built with modules,
+in which case it is required.
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200213004752.11019-3-dja%40axtens.net.
