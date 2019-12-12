Return-Path: <kasan-dev+bncBDQ27FVWWUFRB55TZHXQKGQE7BD66PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4342311D0B9
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 16:17:13 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id z21sf1767735iob.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 07:17:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576163832; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIZJSsF7qcS2BBW1nbuJ5AIkQhsBLsPZPh1HUFAP4YkeS86af1JTT+yQZXTYgMg6+b
         a489NZO6Q3roVF1LqCad/LgVs6gJ2YwnG0ZcDZl80Dhni6uGqFoUZh7AHGYoYjn3sLvc
         lnTtWwN4lR59i/IFdTl2JKmUyJEQWNE2IKthzg5RfHlTQ/AdUy5ssVXv1KPEFVi826XQ
         8kbrB/omO8Lv9973qkiXVtUi9CGqaxJuuenbU5UsWoo9WjSudKO+Dsyr7OGn+P7H2+wD
         hql/zM7ia90jI4sLjraTJ14ST2Joqyg+b5dQbYzaCV5wag4Sa/4gbmrbqF++oZK5pnlW
         IgjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ovdu5DD79kJaAxCTGMmj5Kwcqh7xykr/sDKO6HiOh0Y=;
        b=wRt2w3ujk8T2oc7ZRCzUgUbFDPYVWGcN8G8OtfHD8JDALCtcMl+GjZ4hZBenCVaI52
         u42n3FInLpIXibcN/3ZQXS5ZEcZ0VcxFpOTM4CdHwRGPFhkOlpnzNtG3TQAqUaCogS3i
         UJ9cpAvVCyCxcWjyuHIdW8hbOFJesSEDoHXj8YTCsbkSoFZ3+F8A/yuJzv/jNsyn7jZQ
         +lRDme2mG50s18WA+1NFJ5FFf153pY/KiL0zUfEVDx30FDMdgtLNa27Z68CZkB8H/MJi
         yjZ7/rtLPmS8qesYLp0Ldn8FvcDmydUmAIvopZg+i9VPnQwdK9AipPoltGyzr6XNB1vf
         He9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Oy/hnAfK";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ovdu5DD79kJaAxCTGMmj5Kwcqh7xykr/sDKO6HiOh0Y=;
        b=j1MHPer1ljYpzYG9m6Q9JNGHGkp1KqvOK89nrq5lsmXKd4TupupYm9S8m3tYOXGde2
         23cXLt9wQGgD/VL/9ihRKYC+4INXdiYFWvmvSeRQK9f1J/xKv5c4TRBU+y3gQvq4N+de
         PkS8MNjsihNYwP/OfSt9BATwZ0lgD/K+c7kpL9CkkHIXK7W7iDy2FaT0nozSa9EH3UmH
         iPjPJ1i+AXAIQKvXBMj0E3sUp4R9WbkWS0Py2jTJCc0JYpyTqHslq6V8rR6gCPpQRM6J
         DKygk/PKRjVyM3G955QrD0Jsr/6tpyC9zxEa2foSlsvSgcZ6YoSK+lcvPtEuwyLyAlac
         rHkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ovdu5DD79kJaAxCTGMmj5Kwcqh7xykr/sDKO6HiOh0Y=;
        b=lOgYJK7vNoFHm5ac47TCB3LcX7simiWRQ+UsLab91ZzT+Ri2F5EBg/iosrNfPvNzwK
         SogQQFMYb2zoiEiKdJMcCslyq4G19BGTVUQaRt7SBc0fTB7eTwbBDgST0xIve/tpw5OF
         Tare/aKZokffbgMNUQh/aTi0GqIbrPU9qjVBYIU1Tp7KA33QH1lBHYfpQ14RpPcWZaY+
         AmLpQa7E6d+KW/s3krbQin52ea4BA9nC1PkXqEKxnclJSAALZxPAPI/V+dP13KsLVSQe
         pd5WTqUzKaOwZx+u8MW8J0UCLrhOmMkgbAV9j3uk+RQZDZiI/ZxLdkLXNW0076LbUPFY
         IaIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWjw6QTM0bpieIaroE9+RZ8+bow55LzRs66PmF35ozmMYPk6UFd
	WVQb70BNru9Wa0bykTeqFO8=
X-Google-Smtp-Source: APXvYqwwBYJeM07gr1MhmHdTjs3NwX8tmcg7SYxoGfVZAcncQbwMXn+Az/uAOF22IYO5yQarTWgC5A==
X-Received: by 2002:a02:b602:: with SMTP id h2mr8598165jam.20.1576163831993;
        Thu, 12 Dec 2019 07:17:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:dd4a:: with SMTP id u10ls215351iop.5.gmail; Thu, 12 Dec
 2019 07:17:11 -0800 (PST)
X-Received: by 2002:a5e:8e03:: with SMTP id a3mr3562968ion.137.1576163831532;
        Thu, 12 Dec 2019 07:17:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576163831; cv=none;
        d=google.com; s=arc-20160816;
        b=hcZSeQTEEGGZC/cqx8xqn60jW0PzUcReI7P3nbfMPfHLeYXRJI1HugTz/vexIZXqV1
         qg+1IPdDrsHV37YzhLuF1nNknFNfvdPC1aW7nn0GkNLjStH65y0a/TI+aOVSlyBBayXj
         3E7pvipTlkjqZgsMe5Z/9Bmb9/t6va9qoelmL+zaEQJ3Kc0eoX8AiSoLDLFYuXw0Sc6Q
         1+kd7sMoylzUHacbPqLWns+dz3+8H4hy5x0z8Rq0UBawyCs0QBcKFiI4NlpVko/34ZQW
         wxC1jo42CptDRjt5SRPH2edD/KwM8pdV8cVTnD2MwM2X/RiZeGwQUqvttwDtRgVvP9xz
         n2CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2sxbAlXpABK/W64yfjeUTt7MDV8jfwT8E3maFR+CaL8=;
        b=tRJwZ8qRBC3QaggpXa6SFC4av98hp58NFtP20pWDqg3GulWqkYCCvCGGIXULYCr9Iw
         bKm8pCu9SipOTmTzciXyAM2EdSY6G43qMd83WSReKKv6PvsSFScdV7riKx+PI8jFdk3q
         EBY/cwh3Ybtjs0/lfEyea4soWUYnMxUCQ5lCDacg36UjVUNBOrgl9LUEzH+RnmzDwkNo
         SmQZGoZVUYpzEK6LPN7GF3++DHIbLWhtPWmF2tVOgxaLMcnlsM/cihHv2igDNWEByXH3
         Goj9FswEZsKgJIdooSSkfmnDG8kulhj7EYqUmCYIE8rJt8PltufElqIDcoaTe8OM9pa3
         NVwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Oy/hnAfK";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id z20si241182ill.5.2019.12.12.07.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 07:17:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id c13so727157pls.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 07:17:11 -0800 (PST)
X-Received: by 2002:a17:90a:8a98:: with SMTP id x24mr10744727pjn.113.1576163830706;
        Thu, 12 Dec 2019 07:17:10 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b116-2689-a4a9-76f8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b116:2689:a4a9:76f8])
        by smtp.gmail.com with ESMTPSA id j125sm7954574pfg.160.2019.12.12.07.17.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Dec 2019 07:17:09 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 2/3] kasan: Document support on 32-bit powerpc
Date: Fri, 13 Dec 2019 02:16:55 +1100
Message-Id: <20191212151656.26151-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191212151656.26151-1-dja@axtens.net>
References: <20191212151656.26151-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="Oy/hnAfK";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
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

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 Documentation/dev-tools/kasan.rst |  3 ++-
 Documentation/powerpc/kasan.txt   | 12 ++++++++++++
 2 files changed, 14 insertions(+), 1 deletion(-)
 create mode 100644 Documentation/powerpc/kasan.txt

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index e4d66e7c50de..4af2b5d2c9b4 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -22,7 +22,8 @@ global variables yet.
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
 Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+architectures. It is also supported on 32-bit powerpc kernels. Tag-based KASAN
+is supported only on arm64.
 
 Usage
 -----
diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasan.txt
new file mode 100644
index 000000000000..a85ce2ff8244
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
+Instrumentation of the vmalloc area is not currently supported, but modules
+are.
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212151656.26151-3-dja%40axtens.net.
