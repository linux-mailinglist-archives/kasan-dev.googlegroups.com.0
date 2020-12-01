Return-Path: <kasan-dev+bncBDQ27FVWWUFRB6WYTH7AKGQEDLFIOPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A1BF2CA7F1
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:59 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id w1sf1471957plz.14
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839418; cv=pass;
        d=google.com; s=arc-20160816;
        b=evx+Mqg2AqIA0ZvuwaLD0/YH2gRmJUelRmfQRydBlRq6hJ0cdGwf5cIyELwvAiZehe
         CYuypziolP0YeDn9QjkADBkz08AFv9UaiGLPgarjDBgepR3E6emf73CDlrw0+VoKCSsv
         R32SG3MzJV+6OKEELS8lia8DEjCcIx/E8zQyfWRD7nDeWovxIdwk+uQynMN7ztLIyu/w
         NSEao0gPk1Xy66Zq1lmE4T11i3IalV5606hPbuHxEf9oglE442fnG10jcXFpdXYVw0Ew
         DoGHuBAVbJFAKMhtoHCUdUpDcG2ly+2D5ipmuentIpbDAKCTevfUifJxa1TKJplQYJQJ
         xhGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RBhn0IYfudPWvaKpZIGs2WxlXAXkOwfyXLZuZp4Aqw0=;
        b=nU76uMDrfEOVRu2lCjgKZY085D4COz4eurS6+L5k16KqlEiD1PivbkupqyKFsAzm+4
         YRkufOz3r+3eay9hv8rTQN33bqRwCOZJYrR9oJbdhiCI9HjHZFjINx4iZRh78RTliTC3
         wOk81MUvXJLf9bTFLs63sfCbK2hjJjjuref9OuFR4emDjL8McnN9kMMmDtTU4zF2nPvP
         ss9nG1Ym5Wfb4NvTPvr+LjyAV7CanslPQ+vxLVBdn7upHtK2aExsrLTqBhDbcGD8Wrlb
         8WU8gF86y2fcadmu4ONnCFnjMsiRFeI0E3LJlnHTOKsRzAxqdnJJXdVLBwTrPeVNobeT
         5Raw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bNqGOi6P;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBhn0IYfudPWvaKpZIGs2WxlXAXkOwfyXLZuZp4Aqw0=;
        b=iS7SqjO+fMu9zfB9A1vL2Asg2DNjzqMLeDLz8GN8c1l9Fxdg3hXzR9/wIHXi7C4Jl5
         ybTjxdZhAAaOxLdzD2gj/cKb82sXZVw2N9xTtLDmAJ68QxVmU84mfG4bJrniyHz/NedA
         7ZpfPsNI00Hb1I47JWKuVQnsslYkCxRnIuQ3BJowAn4ELzi5WGs3K5z7422T+njHVwkZ
         xkjgblV1YATR1PFZS9S0p7OkMeIeoXE6As1j+FfG/+sxF43OXeHp+/+pjECPY6V+acPy
         Mg1C9nbo8wdtpMdYRqk6F5LyzoPMMG3YLCPbWuAL+UaKmZg4PR0K55op7+BEZZ6/SSpx
         9plA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBhn0IYfudPWvaKpZIGs2WxlXAXkOwfyXLZuZp4Aqw0=;
        b=RJkc6up3+PMOJnZ9ENVVNphALSJDSmxUX48ancecB8gW1SOG95/15oWOtL4KVmV69d
         L5QuWSOErr8T6Rte5ADVeZyfrQ9hTJINbwgI6gkn0K4FZKL3gncvyszs9uRj1dlQr7V7
         H/tMwtLskIsKCNuJYeQIDnYNfi5OQzxes1tuJlgZaDx4OFTMGdHUCgui3YyXjmSvCk/D
         Cs6OLqU9OylCX8s8Ic+EpiKPzmy7eI9yqUN05kJwKnwseKqeNbohySW4xRJ6Ku0bfdhx
         Ux44rqMl4Z6GvR5cfhY/l9InS6Qrr+013KO8pS6CYGjoLkUT6KB1lzDonyhblKE1gUtn
         fERg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UIC2uFEsqE7uMq+AwkpCj5wgkdweMQUSGnO4CL/vFmk7FJdJW
	SiCthN9YJOcWZcIORozYCcU=
X-Google-Smtp-Source: ABdhPJwdkryY8bybp7QR6uKHtNybl7cBxr1f782lb8+qzQfRNdwyWBpPbS9XpOkhiTxC9L3AAuQOPg==
X-Received: by 2002:a62:8cd6:0:b029:18b:ad92:503b with SMTP id m205-20020a628cd60000b029018bad92503bmr3166595pfd.77.1606839418174;
        Tue, 01 Dec 2020 08:16:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7a88:: with SMTP id v130ls715351pfc.11.gmail; Tue, 01
 Dec 2020 08:16:57 -0800 (PST)
X-Received: by 2002:aa7:8254:0:b029:19a:c192:5ddc with SMTP id e20-20020aa782540000b029019ac1925ddcmr3193131pfn.26.1606839417616;
        Tue, 01 Dec 2020 08:16:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839417; cv=none;
        d=google.com; s=arc-20160816;
        b=U0esX7zRj2vHv+efDQpq3/zEgt7BSvoSgxTdpXXKUXU+4vCFLnpnKyr95BRZKlGEuL
         4C2qjg1DKf6TcLe28P06EP9f4rBTAFOXt9Py3XWaLJdDHldWAr6Ia7ThZ7CN8il7xNWM
         WievHFihpbFV9Ydx1y3JxRtortoK4/4f5hTDshX9YKf6/86yBpO9+EziJH36cxuXV/Cf
         pPNdyRSjBi5im7g+Gf4NWcQubyjE8DA4YMI6B41tvRMLpy2PEIAqH9kYXNXIuApMyaSK
         aftPxCZhs8zYLnooR/HyfLcMU1c7G3ipu7r5t4m4qhlen8iItGJ0lpCxySOD7eGiGAqK
         lLMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s2vaNiCstBIb+WWFV0QIyynMgzg46gv0imUofC6H27w=;
        b=xBQAZwreNWqn0aDp3h1kNqisrw6cr3mIjzF7R6QrGCf+4QbEXubWJFzDruP6hVKULT
         Vf0cNIBo7FwwchsaZ+Ut7II/DAhZ4UTSjGn+xZ5gN+4lHq9xLUjUkyTN7bOiVkRpXtn7
         T266Hs6ueM9MmeOcdoOa+7HGA6k9eMSsD7qLDiFCKyxa8x4ZVphH0KddDrCZicfVSA0s
         Z1UPokK5o/krKVScNcRu/b72gX2pfi5+AkI0J6HcsqMPIpXcqqERQjLeGTauz4CTbVj/
         yvzbM+VlLRZW5iSXpmSxiMipf8p7iO/yy4cKr+IaFJMUEFkwj8Jf4tmTf6xRQfGRdbYy
         nM7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bNqGOi6P;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id d2si17606pfr.4.2020.12.01.08.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id h7so915900pjk.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:57 -0800 (PST)
X-Received: by 2002:a17:902:6b84:b029:d8:d13d:14e with SMTP id p4-20020a1709026b84b02900d8d13d014emr3544651plk.29.1606839417392;
        Tue, 01 Dec 2020 08:16:57 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id y5sm220594pfl.114.2020.12.01.08.16.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:56 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 5/6] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Wed,  2 Dec 2020 03:16:31 +1100
Message-Id: <20201201161632.1234753-6-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=bNqGOi6P;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1041 as
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

kasan is already implied by the directory name, we don't need to
repeat it.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/powerpc/mm/kasan/Makefile                       | 2 +-
 arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)

diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index bb1a5408b86b..42fb628a44fd 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -2,6 +2,6 @@
 
 KASAN_SANITIZE := n
 
-obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC32)           += init_32.o
 obj-$(CONFIG_PPC_8xx)		+= 8xx.o
 obj-$(CONFIG_PPC_BOOK3S_32)	+= book3s_32.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/init_32.c
similarity index 100%
rename from arch/powerpc/mm/kasan/kasan_init_32.c
rename to arch/powerpc/mm/kasan/init_32.c
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-6-dja%40axtens.net.
