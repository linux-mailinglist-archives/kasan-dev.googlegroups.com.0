Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7X5XHVQKGQETBBDVZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EFADA6BF6
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 16:55:59 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id f40sf14266178ybj.2
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 07:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522558; cv=pass;
        d=google.com; s=arc-20160816;
        b=OzkJE2VUsSKOFtkcJpN1Ui1empLn9ZboptCQMBocUtKZWZq/OwrCi87tzqnOULwC/T
         qxsx9wLvKgK2CV/tM0kykyUTw/TdTk9dP6mOUIq10oUgkw7dVaOVtPxS1TP5aSuTGGnA
         aklPIM3BqnrOby+iH1SG6kHD1aE69TtRT6qzqW+WYdwxpc47d1ASWlagw5OyAETkcXCQ
         hI87v2+37KbPI6gCUzZT4FMJ3V1s9kEoOCG3qgEs9NigzLzL4SB6DyHcHglg/W83uIgQ
         8YNRvJ2cLvaruhNdrKpjBpddI128Sf4YWPSsT+LlkiUZ1bGvCsPzCtXk9rtBpiPWKQJE
         tRAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=d5Ycni0vMIjMPIqaCNrOi5hN4RF9PC+11ztDJ0D3iuI=;
        b=CmIblX1l3G8QL5c/oyN9l+j3EGNqpKxwIpO7055bu84kmb0auUIx86btmqeziBOgSn
         OsQHXFxSR20Muuu2tEt8ct0urPP6d0iUuZh6E3XDcOlsn46W6oHUTACsIs/31+SR4e3n
         FkyKUjMSyZOjHol0kLrT3Mc4zyovl8PN+WAP3f1V5aMhIm+i80YeYnSXj2rHVYV52rd7
         gCP7NqtsV7BLVSbVL00+YCj6o6CuewGI3BzOpomkbp00SRjwt7ZnImzQAUxGjzBk5+UW
         UNMSA+n8DO1UGsEyz75LSYCuImp+F0SnRuB0rwVfzV46uYFhvqOJ+S/ICf3tnxjnvfuq
         6iBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fYYdJo80;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d5Ycni0vMIjMPIqaCNrOi5hN4RF9PC+11ztDJ0D3iuI=;
        b=Duca9asRLloEPmIoreKw/vz4wvpCDDdnmLuy40FajlUkOBYb/EWqWtCtNwzPnq0f5M
         VaFdYEi76zRcOd4YI3wiOe+GQvCG6bquYO/17XWeKimp4GsrC630ogbyzBl46k7fmEJO
         jbj0N7MEXr4B3QWsBXSUi1dCHi6TK50GI6cCnbq640WmJ8s7nTkwi3GdkqXG+MRMe++g
         XfnpfIkm5edwT5SQrizrhp72KeSLgUVLa9eEUTo0ysL40vVW987PuOg/zuNVBwrpso1v
         JOxzNZjr1jblV4beT/OxkOf0rfQGip/lcbNExWfHjSLTn/oeyLTCnowNREVACyylwUCK
         lLew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d5Ycni0vMIjMPIqaCNrOi5hN4RF9PC+11ztDJ0D3iuI=;
        b=QL4I+4Jg0BbMgnZB7cE0DLci0eM/zwa+ia9dPU6e625v+MAcp8D4LhoAcxDTHrocK5
         V8u5xS6RtJ/vf1pxc5wkAAuHH6Xs0PADl8fTNifT5alFWZeq7llXZ4l4bryFWJCiOoEs
         xRKQ6UmqZev6dJacFhAFsKum8ymWMcDDxlvr6MVUfF//to+heI1QpmuIxN0blmZIEb6W
         9mjwxYCcMtzyD1ZyK+Jti9G/X+VRi2+CDD3j9NjiX4PMxU8IzWG413RL8FnAVAh07HNK
         R1dfk6Wvy//P4FLO0huWJMrKarzhp2PZH/7JhIVT6eg5Ikct/a49UArjKfV4idY4r0u0
         Qw/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUoh4aDo2RCzFsf/0NjZyxq1chZ45c0iFBCnXhfD1iKZp4ybnIw
	c/SGD92ZqWQTvclIJiHCv2c=
X-Google-Smtp-Source: APXvYqytEWCRvbA8nHwgRt4Zhd0qzNfdD2a2BOgRor3ZGBZgrRvoqP/RxmHd6/kZF/Y5LxDU5JKLnw==
X-Received: by 2002:a25:d0ce:: with SMTP id h197mr5132240ybg.143.1567522558331;
        Tue, 03 Sep 2019 07:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4303:: with SMTP id q3ls2379824ywa.1.gmail; Tue, 03 Sep
 2019 07:55:58 -0700 (PDT)
X-Received: by 2002:a81:608a:: with SMTP id u132mr26137518ywb.474.1567522557999;
        Tue, 03 Sep 2019 07:55:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522557; cv=none;
        d=google.com; s=arc-20160816;
        b=CQVstb05A5Vju1zHPDu0/GosxCJUou2TIl6vP0WfR4FmBgGOTQjb50MN22raksSrvV
         hSBCgOAPeQ2aA0c1c6MMrPoDJ+IVqdyctPyl4bDRG6bEuVsvaXfkA22vqpbReFb0wS59
         JZdNHOeNepSHsUYimHrhsJzMKtMolkMo8FeKKtiB8gg/JUKgOW9Cev8Uew/BnjpM7Bk1
         eyEve7Q8B+VvLSKYl9ALp+n5C6egvTpKmUZa3ZjtFOZDoWP4bt04mflLppH9sJVN9Aal
         zg8Ze4keIjTsdoYgUyz6cAJohMAcJ3M/9EzhW84Y2n8NhNCtzrBTS+wBvYdB122ucIwT
         HoEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ltnYvwXNt85pQWYuu3Woofu2pXYpHtCxsiErjju1VKA=;
        b=Nsya2gNhlFKn2e2gsrfWtnUCcPqvWbqZK7in41fHmcdUoDIarfIdaPIzKDcN5LkMm8
         Yf6zd4bXkQzJLtd9EWkvqM2vlL/LuabPqiGSoscZedk9LYx63NMZvVR30oJa4xROHyIE
         pmXlq+/w6ij6/vvyAEzTKdlyDsnOcXQdl1a/0pjooEpiKnbV3zqmWw9pWesweK+jGZXn
         mj3TrV1CNS250FiNQoEcK+j1PgFyq4sxCRY48PzKLkbR7b3sOtUbz2FRqkUW/eKclPZJ
         5tL8DwasjYcG7h/Pl9EBfD0RsInhhsjdBtdw7q5uG2yg6bKBSddwnSm4sddvbdhGf529
         F5FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fYYdJo80;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id u187si466158ywd.3.2019.09.03.07.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 07:55:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id w11so8033027plp.5
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 07:55:57 -0700 (PDT)
X-Received: by 2002:a17:902:720a:: with SMTP id ba10mr33715784plb.231.1567522557013;
        Tue, 03 Sep 2019 07:55:57 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id y8sm19975257pfe.146.2019.09.03.07.55.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 07:55:56 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 3/5] fork: support VMAP_STACK with KASAN_VMALLOC
Date: Wed,  4 Sep 2019 00:55:34 +1000
Message-Id: <20190903145536.3390-4-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190903145536.3390-1-dja@axtens.net>
References: <20190903145536.3390-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fYYdJo80;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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

Supporting VMAP_STACK with KASAN_VMALLOC is straightforward:

 - clear the shadow region of vmapped stacks when swapping them in
 - tweak Kconfig to allow VMAP_STACK to be turned on with KASAN

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 arch/Kconfig  | 9 +++++----
 kernel/fork.c | 4 ++++
 2 files changed, 9 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 6728c5fa057e..e15f1486682a 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -843,16 +843,17 @@ config HAVE_ARCH_VMAP_STACK
 config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
-	depends on HAVE_ARCH_VMAP_STACK && !KASAN
+	depends on HAVE_ARCH_VMAP_STACK
+	depends on !KASAN || KASAN_VMALLOC
 	---help---
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
 	  caught immediately rather than causing difficult-to-diagnose
 	  corruption.
 
-	  This is presently incompatible with KASAN because KASAN expects
-	  the stack to map directly to the KASAN shadow map using a formula
-	  that is incorrect if the stack is in vmalloc space.
+	  To use this with KASAN, the architecture must support backing
+	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
+	  be enabled.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
diff --git a/kernel/fork.c b/kernel/fork.c
index f601168f6b21..52279fd5e72d 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -94,6 +94,7 @@
 #include <linux/livepatch.h>
 #include <linux/thread_info.h>
 #include <linux/stackleak.h>
+#include <linux/kasan.h>
 
 #include <asm/pgtable.h>
 #include <asm/pgalloc.h>
@@ -229,6 +230,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 		if (!s)
 			continue;
 
+		/* Clear the KASAN shadow of the stack. */
+		kasan_unpoison_shadow(s->addr, THREAD_SIZE);
+
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-4-dja%40axtens.net.
