Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNENUCDAMGQEW2ZCSDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FAA23A7376
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:33 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id q18-20020a056a000852b02902f93b26d6d9sf3659198pfk.15
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721652; cv=pass;
        d=google.com; s=arc-20160816;
        b=yL8DGMLKGZhzF4kcz2NN9SOnPBDYNLT1bKswrQV9G7nbaniQTrzWuHKOfWuvAwTB4v
         DFllWVkJ2fXG1ox9Vi7IMHLI6ivBWTvoY2ER1eQxjYVbiNPR8RItPHTwDNTziDorVKuj
         4Vnrbt358wpe7Qgo0KFE0DPVX93ZcbcOwXyE6CKNJ0guGM9JGNObyi3HY3w9LtjLDpSu
         Vmsl81r05EOhYqr0NTKJURZCmN8cVvRJ8tLgSZLDCu1/Uik1m8vdnknJS4W70hdzo8le
         QeXShDZ8KiwQCMMdqavZn2lsTYiXwd5LKGLxPXr635o53fBQnh91A1Mz8JxpXBtnkWHS
         Kjog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pQtam3WhQS6Oq7jth4ioQ/8HW5NcAq0UQDbES7Qh8bM=;
        b=tBOwbmqFDeqUtLeAbcAGSXOk2+GZ6XP/ZZzvlr2U3YxSxo5rtmdxopGkooQwPxZbq+
         7iXExJg09/clip0JSuh36mhi73suFsc3ctsWZ8fOB0BkoS66UdvGuHZ63bGtK+XsDOIy
         ORsu95s41OnNZ1OSwUDlFhYbIEMSo4/bi2ZMpaHjOYQqqt2pDyQglf7DDH9g9AFv6UNQ
         CDHX7dI6w0NaOfl2fTFd9TEqKpgHrKZ8w7F6t+oaLqvfLtMbptSygmO4YbYcTokFqboC
         CMvFgNuTlYEMVk5QVYKgEv+AS64MLb3I2zrLqMj0JE+pz3GykS8AyoA8LHF1DaV24CLG
         PDag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZeJTQLnh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQtam3WhQS6Oq7jth4ioQ/8HW5NcAq0UQDbES7Qh8bM=;
        b=FwtgAdjESrulL+uGLGt+sH2THSR6GsrjmsbTz/0ZGu2ZQ5c9uh2uGZWXNDuXJzQ3SV
         S9J0t23tJF0BCofFz6KdjSlc3lgZk6fWJCX7A2cc6Dvlr0iCsjZlCfKH7gBJ07B8nkUY
         PhtGcsD218KzWx4c5GuWLgm0neDEEWG3dz9hgW2hJHui0miOQtkJButKEfq7l7Y/DPQ9
         t2AsjS3AMclBoFp70MthyxQ8hOUYRhUzup1JHWPeVBB0DkBspJVurh4UhC3tNB1LPjo1
         P2qds4FDvF1hSdio3v0rth8aDCRwjxVABbMxdUkpa7E5eih1bifUOVPrr/PMiiN3Yxoy
         GT2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pQtam3WhQS6Oq7jth4ioQ/8HW5NcAq0UQDbES7Qh8bM=;
        b=QHc7CMGPUSQTTt6jC3NCUITU2j1Sww9CUfw24D70hjXeft/5day7mHOv9RA+Lsz535
         LHU8ud6Ehx/IAxN/Aday2FvVPIFhdrt15G/Dv5m3zFOiXmEsJcliCv1y7O7mOCEguE2v
         iOGxg8RcS2qOvvuSLrsbKKcJZKQ8fzZweBfBTe9Jw+NcN715cFtkQfhv2j6/EalyWQzF
         ZMvC73g55HZlqaO6+dcvcFRRNhhGrMLOt0oxmJfzIU8FCcMFCBO2Lljb0eByZfjUpNsT
         Gx2lE9DXbKEprEHmuiSVAvFq69HTQlX/uZ/b4hTBGtBx0PEAc5alo54JEZkoQaBuMwWt
         X8Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o/lPBMybQNnq2OMEfudiOyDAZjgZ+V9430H2MK/WIUmVED9PW
	nI+n3mPS+To4f9HaPb/h2dI=
X-Google-Smtp-Source: ABdhPJyX9aBQhYCIEqPOwgiC5iKvwAgWzt31e4UgFVuFAEl2yEUgHbg1xphn21YIAxQoM+THrZzwdQ==
X-Received: by 2002:a63:490f:: with SMTP id w15mr19999856pga.352.1623721652238;
        Mon, 14 Jun 2021 18:47:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d4b:: with SMTP id 11ls8796206pgn.5.gmail; Mon, 14 Jun
 2021 18:47:31 -0700 (PDT)
X-Received: by 2002:a63:185b:: with SMTP id 27mr7007212pgy.164.1623721651759;
        Mon, 14 Jun 2021 18:47:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721651; cv=none;
        d=google.com; s=arc-20160816;
        b=ZkixfyAClODrhUZVcifJMh7jAcfPme/iT7zazTIKrUdQGeBPSa4bLFuiIx3nCNODCY
         qThaFOg42r4qyd56dqqcG9GOyW/Bxs65f7HDQKUbJBK/neakZi+1Nx0GGA01Ik6/mNQ0
         gCq4QuYwr8PqaHtF3/vbXdtIqn9do1AsjQZut2W/xgl5N4mMnO4ZkpEumic5ESFGjDjP
         nL5B2QAkvw0QQ5buF8kgQNEDVJ3Qui2eyvutcDEdV7Wq8LpydK4xWhYFycR7eLHjqVKu
         YigVYkbXVbmtZji58YAcY9VTjh0NC5yKinCt2EFTbW1A37glWfLygr5X64Lb9emxr13g
         +Suw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yq2AQYTBwcMSkk50BfF3YUyk3WvoM0RKP8OIdZyLogM=;
        b=Mk9hkhHzTj34fphmw8sOHVZmHRNbsLSk2vm5dotCARIQ3Tn3g/Bfe4OYgVytFnzYVH
         vwzLZVYR6dIR1CnUulpvjrH2kifnqXjuTa2gPq4AE9y9XegVjcpU5dzl4b2qk+lhaDvA
         G+6qlk5hdZg/fVzVluU+vnSIHnrnkbeQlvqZY/hWRtSg//tWqhlKDuy2RFcVs/OXS0X6
         ujgOb+QHZwZT3759ug3YyxTJiGwKhU66p3j5wpmeEUkXbH68rWTaC21ouvp0MYKtE45U
         aOBjAlv5qOhOcRBO4s3wU2JiwKld5vxfO9pHqiPZbuKYVPupzb3pDL5uGPkCad9FILHH
         x12w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZeJTQLnh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id mm4si220897pjb.2.2021.06.14.18.47.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id g4so10872809pjk.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:31 -0700 (PDT)
X-Received: by 2002:a17:902:728e:b029:101:c3b7:a47f with SMTP id d14-20020a170902728eb0290101c3b7a47fmr1630411pll.21.1623721651578;
        Mon, 14 Jun 2021 18:47:31 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id t62sm5508747pfc.189.2021.06.14.18.47.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:31 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 5/6] powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
Date: Tue, 15 Jun 2021 11:47:04 +1000
Message-Id: <20210615014705.2234866-6-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ZeJTQLnh;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as
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

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-6-dja%40axtens.net.
