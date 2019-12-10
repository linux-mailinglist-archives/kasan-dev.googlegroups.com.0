Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4GGXTXQKGQENMUUFRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 25FF1117F22
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 05:47:46 +0100 (CET)
Received: by mail-yw1-xc3f.google.com with SMTP id l5sf2589293ywf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 20:47:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575953264; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Jm86fZNP4pp/RfwIoy9le7tJgUqEc8us8n+XHL0xoyIwtYi/b1BvXDRFUGzH1HEfZ
         oOJ1D8pd/f9E18dTvZLXv+sahWbfsp8AhvUfpmFWlKGeY3pgBq9fWDYZmfqLJxoKPWgI
         uR2SuXZJUz4C/tRzYPiXuhLeula9Weo27S+pc2TuMIgXaonp4OXxpoWIdELYJorQN7J0
         3MwqYGP/VYKQbh2pkseqzDsInLs0ApqFlrBSjzi1tIYximFB4xSWlcLQrEixlPMjPfMo
         66+3FOtOnalGhsyP+eFvud9bRYkCNNI3FWk7WJJ+ZKUMl/0XVlbwFFfSWOb7FiqEoM7Y
         eevA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=umZ3n/lpYXpjnN+TFyiNdkIiQmSxT2MwmzKd6LOxaQc=;
        b=Kh+7IoZdFLXSK25HA0Z1EpyM9c01nMOPZW5Nr13CBRH1LzbdKlxitr0Jcr7Qw2Wc3z
         euV3A3CPx1a4B/dKfy9QNf1JUVr7tiepvK2aasE/pRLcKaVVN3IQqIb6KRO2uIjXI6iV
         N1mv70ciRL/gFDtw7h268m/+BK2wyqVk8BRllikE3vJRDpCSbLAz2cuL6GW1FR5E9/pf
         d44CZhbhUL8YY62Hr4JzgSHlE0sXMLTuU/fTZ2yTU8mNPCjmrOVn9udDS74kt0FM5XPq
         +jHiT5x604yrLzmIrnwpQ5syW5P7hW6fxXphGWtlcWFEYQC4M6ZANSkzbV6ozh/gRnd9
         UOzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=WI2BC14z;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=umZ3n/lpYXpjnN+TFyiNdkIiQmSxT2MwmzKd6LOxaQc=;
        b=h72ZjRG3zuw0Eb9sZuJZggvPv2S0kxLxAzR0Cav/BX2pa/JahYaDkeTMPvKmyAbd7+
         gSk54l2ANmC5PCIj4/j+dvcyqQY+WLOazVbb55PO2sjt0FQis5UpTXXNqwxE5IxbmxQR
         I/aW0rO0PtQKVUvNGcNEc6koOm4/fPKeh7wISmhdKxFS6G0VEdbqpRY6UguEnBbExGgo
         NmtVp1oNX+Ob377MP2i7BgRDc/ucOnJLq6cAUcvJTvBtQ8o4Ojz1eK4SvWuAGcap4CGD
         aD/NSj7v25tR1QLvnncwj+xnb2ql/MEgM6Cn9vmY2DWQeWhtg6Ko937S0Qn219Lqj6I7
         0mYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=umZ3n/lpYXpjnN+TFyiNdkIiQmSxT2MwmzKd6LOxaQc=;
        b=CJobdJCI5i3iiJGHSXsdByoC32XBLz55Z33mrixwR+E5ExmGfhebSFlWHL2PMnpJlU
         prH9Bv7UU8BwmOun/uFp/4hpDHszWzKNGHE+9u8u21GTI9yToNUSOxNdL7WNrTTo7Kxu
         UoltGCwHrhXxOZZm9WtemsfxEmqLFV2CXqE3hLEEc9u4BDkoqGqEqEG6k74D0H/4q0xM
         LHcAaxWtfssYTmRHIJzwH//bgKVnodu6kw3ni7tZcK6+5G9P9BDrtNuWU9F5+RltGPU3
         mwozK+3IFEQpeNu2yXXklzeQCwzWI/ugrr1MfRpcEQN7cNbDqOsfMxunAR/L3V88ye3/
         O8Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAULjxZvhHIRMTMzaP9p3RpjUv7/0Rnh5vOdVYomVpPqkC75c4T3
	Wr9OtCVDkKyx5fC/Z1eSsuU=
X-Google-Smtp-Source: APXvYqx2vEyYkR5HzUod2+if5ZNDuGTfk7RgxdhL1jvMhp0gIKWS3KalEOHdwMZUfz8jDM2GC5IpBg==
X-Received: by 2002:a25:9a06:: with SMTP id x6mr11507960ybn.405.1575953264679;
        Mon, 09 Dec 2019 20:47:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5d09:: with SMTP id r9ls2442148ybb.2.gmail; Mon, 09 Dec
 2019 20:47:44 -0800 (PST)
X-Received: by 2002:a5b:58e:: with SMTP id l14mr19823216ybp.118.1575953264067;
        Mon, 09 Dec 2019 20:47:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575953264; cv=none;
        d=google.com; s=arc-20160816;
        b=vbyeoWARWFIxMGcGhIWJ+vyiBTkmPeCBBmJJN6L8CfSIR//qxJBpDX5VYjbAZWP1zp
         d/Mg5PdXmkc/qaqa3dhzfaHe3WKkIp/LOweUl+4LRp2CAw9iiAtSQhfMtaOzeJdLtGVg
         pL8uMVkm7WZ4PGudFP3lB8BMi10McCXw6wlcjQ01rJR9tSImGzfYrSssUPYMBnrzsfOM
         MTP6z6CghPFhVyYo7PYFMF9cXhAfCCs7lw+evOMqW1HN9iMKukfWIt2k6dUN9RjFzW8g
         Ib7i1VXx8HNv4xqeZ8JYzhPK826X6UT19alqIQbszKlC9sK1qjL3cFJOk+xWrzZSBSXR
         i5IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EiQDn6/0oRuwTLnfNvzdiHGZKSMrLbDZhPom2rMZn7o=;
        b=L6aQI6WWp8RaqsaA30qda3zoFCZAsUQl1Lk93dvsdpfm8HE1h/jLw0lu/0exKPkKda
         fQmcWzc0HDA+jl6WFMiq+hopkUnRV0UpHePgq9IyYp4dGXoyWBvGXmF+UM5gcnBakgQE
         4NBLvAF2FJY124JZZdYr8mdq72WARmSbPxxb/Xyx1Oew3brpKOR/iGKdoYtVJon74YvA
         NS3pVvBwVT8JlVNSMK8d3RHjNx9RNJC5vC0J3MxzBBjdYEr8w95SHY5E5wkHsv7ztpgB
         JfkPpKCh9XthObSW1TigKPAz2Gmdd6uaQsta3x9k7qckUNiH8IHjphJ5OvrxBlsjL9VM
         lCIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=WI2BC14z;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id s64si127660ywf.0.2019.12.09.20.47.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 20:47:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id s18so8397345pfd.8
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 20:47:44 -0800 (PST)
X-Received: by 2002:a63:5d03:: with SMTP id r3mr22623144pgb.306.1575953263265;
        Mon, 09 Dec 2019 20:47:43 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id r6sm1166225pfh.91.2019.12.09.20.47.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 20:47:42 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	linux-arch@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 3/4] kasan: Document support on 32-bit powerpc
Date: Tue, 10 Dec 2019 15:47:13 +1100
Message-Id: <20191210044714.27265-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191210044714.27265-1-dja@axtens.net>
References: <20191210044714.27265-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=WI2BC14z;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210044714.27265-4-dja%40axtens.net.
