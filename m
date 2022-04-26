Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVODUCJQMGQEBKR5KBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B36E510426
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:13 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m124-20020a1c2682000000b00393fcd2722dsf319036wmm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991573; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+t/9CgfRDEakYsMBCwUs74Hmacknq2yBG+pNdOm7XAE2tr1yNY+W7h8Z8aeE43NfK
         VA/1dvjyCBAJHUzmGmkYMJvNXZiYMoNKhCG4ZxEUvS0ohSgWmdTlzX9yCBfIstOxVsoa
         5TsyEaW9evlBVWB+LDBSSw75lGTzKScornh+0d9Jf+ai/MS1N6PjO86iHz34nv0cfpya
         BzIgcxTzPIGAFaskycPWPREfW/nQU4jCHvfsQkEHesisnmSlJX+utsf8zx6jFZv5AWVI
         3bNaIpML5T7A/swZQXIDgM9INLzLYMfOTcdqH9IGoyQxBRTaaKUTVn6irGJK15ayomKk
         IOWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7IIs8YBlXrwOX7iO75r0Nmct6K+4LkpASzjcTz/t35w=;
        b=ecJtifeVfdjJm4kHc30bJPY1YFzTknqivMTBzzCjhXAiDgW3VHauKrzpSUiAH//1Y6
         /eqzpKlqiXTW+HdaxNtip2LeBbwEHVo/NCdPzV8uHm9gDUMsbAnnroCP04NRK+Z31+2l
         ikS+ue3QebG6RbRmY2Lp1SxcWwM0k5XIh6HsP4VgVLbpyo+a19qoqVa5oJEzB5lSTcUY
         UurHEVPEo69RqUnrzmk00KWULLcJ1hqtK+43VyKaC1frlGxjRhe8v24hogJVlYgKVGIF
         U4Y0hbeQBcZ4B+jruTF/AcYvFHAf5Tp5LWvC2wVK2yI+TDWfdyZr/034askHIK4ztKWg
         xwLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cLDKsrGh;
       spf=pass (google.com: domain of 31cfoygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31CFoYgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7IIs8YBlXrwOX7iO75r0Nmct6K+4LkpASzjcTz/t35w=;
        b=ob7MYW3b9h/RqlayY6QGe+6YVHHJ6FHved2ohNc2lDvyUFK5wBusJGXzokqIHdtlAJ
         4zrJ8Gbo4gAQs5/OO70iacwg/C5VdoJj0Dl54soNSX4zhA2U3gCV9KxOFHjb4MQeCVq0
         ZeLlYHhgqTCbW4fgVPBFkTs+Y5sZb1oT5pVtqeaox7k7KbjQO+mkVg9gipS7QsTG8iHu
         lXuU1GEIedhxJyA/NAe9wYC1QUrn4czhnFHILNdPqZ3lhg8tTAelBlqdS5hwsbN5Zz5d
         lyTvkSCM2RtalqvkyWc/loClNoqUNL4APMCrfgZib+y/5ixATuE2l8FAYJrk6NEb2lbg
         aFnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7IIs8YBlXrwOX7iO75r0Nmct6K+4LkpASzjcTz/t35w=;
        b=l+lA1WYEdCSQCvPw2pASFkSWGp+2V050E1bfpbHSlwDhWfJTLSU6rT2U2/2opvvyXi
         A/eb8zGlMqvRjsbG3Vjg1gPDC69itJeak7vLpbqciWq4RVc13DvS+6fc9ryDA8FGN4Lz
         xThHAPe/nZbg7Tsok+1DFS6prrNhpnUoLNkRQfDcQctYb/wgOeNZxSTg03x4bgDwDje5
         Ln8YlcSLplkI/DZyizAT4/Gct97to7bo8Nsbd1W4PKQS7at3fls8+lS+3bt2NmTuu6hH
         ZRexatEFH/WdeK2HcES+Y7dTJyMQ3pbxRFUzZCNIx3XpwqfDc7EeM89WVyURgTfR8f7r
         e6gQ==
X-Gm-Message-State: AOAM531E75RFPriuroJTLkZf7GuUxOGCzCvVx50a05CrbaljRDHQKpEv
	VrnHeSIqQyllrSyESopde/A=
X-Google-Smtp-Source: ABdhPJwV2PnpSJzruN5fCYlrrfljMdtkMdn0cAINisMyo2BMxWAtA3mnHTdR1H7Fl9aXI99s+FHmRA==
X-Received: by 2002:a5d:584e:0:b0:20a:9034:e312 with SMTP id i14-20020a5d584e000000b0020a9034e312mr19689542wrf.518.1650991573370;
        Tue, 26 Apr 2022 09:46:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1447:b0:20a:dc13:2578 with SMTP id
 v7-20020a056000144700b0020adc132578ls1008065wrx.1.gmail; Tue, 26 Apr 2022
 09:46:12 -0700 (PDT)
X-Received: by 2002:a05:6000:156d:b0:20a:e015:315f with SMTP id 13-20020a056000156d00b0020ae015315fmr6595529wrz.140.1650991572474;
        Tue, 26 Apr 2022 09:46:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991572; cv=none;
        d=google.com; s=arc-20160816;
        b=QOhix/hzcY+lIapSG9W1m52flV2dxMMtkKnh//YeoUEzoNxkz/3gt2c4H/MLkKQt4B
         cuNZQYuouMtjRFh0REjn0C1NQbq9uvzfbosgKnOFQYMbkdwRDxcGOom9qi4ChLqkDb+z
         2g7roh0h5iohiUgK17O9CfTJmjJyCzQO0JMf9YEKuDYE0CXG/SFwqGq/mHjaRhWef4Nj
         AUKJKwMUt1f8kYHhLBAewiHCvvTa8FTe4sfymZGgNBFwZiNeDmkRmn1p2OmWetqsOp9n
         8yIxjgXaH/LE54F4jWDoBajrnMhsnL4g0ZYSUSM/KCKuECebI95iiNO79XuHCmQIC4kU
         n71A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=moZadDgSRgKTD5MeByPAKBz5Srz/DkBZpKo67JL3wX4=;
        b=HPYEQAiQUAZDzvuY5OCOTYahP1n92U/CzZgSfc1kNUXeZPBMXHIuu6YG8aiVA4WmeF
         hvlgyp8StDJh4yRXR1pSoARv+kVPXsHLl9LQl4DW8Yc1hKBU5DmJg4dPEdH1Y+/+JHnI
         X+Mbz9Z3e0UX9J9EyBYwX4qs6fT1buNgG8DiRBc/VzD0avPlN7cZ8caUHDpZ1b/gML8c
         t6ePI0mdgx44pX/xDbwpLXAnyi2bTG008VYOAteUHkrh8o8GzW0t7tB2cQWer3SAWtAa
         Dz7U33/q1iwGNFefNWmzNSTAnIMZhWtqeWaDuSPq66Kh+3hjFBfx+qL5AO76kwhI/p8O
         oGvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cLDKsrGh;
       spf=pass (google.com: domain of 31cfoygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31CFoYgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x20-20020a05600c21d400b0038c73e87e1asi203492wmj.0.2022.04.26.09.46.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31cfoygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id k16-20020a7bc310000000b0038e6cf00439so1111600wmj.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:adf:d1ce:0:b0:20a:e668:8927 with SMTP id
 b14-20020adfd1ce000000b0020ae6688927mr3156284wrd.508.1650991572003; Tue, 26
 Apr 2022 09:46:12 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:12 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-44-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 43/46] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on
 x86, enable it for KASAN/KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cLDKsrGh;       spf=pass
 (google.com: domain of 31cfoygykcde38501e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31CFoYgYKCdE38501E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

This is needed to allow memory tools like KASAN and KMSAN see the
memory accesses from the checksum code. Without CONFIG_GENERIC_CSUM the
tools can't see memory accesses originating from handwritten assembly
code.
For KASAN it's a question of detecting more bugs, for KMSAN using the C
implementation also helps avoid false positives originating from
seemingly uninitialized checksum values.

Signed-off-by: Alexander Potapenko <glider@google.com>

---

Link: https://linux-review.googlesource.com/id/I3e95247be55b1112af59dbba07e8cbf34e50a581
---
 arch/x86/Kconfig                |  4 ++++
 arch/x86/include/asm/checksum.h | 16 ++++++++++------
 arch/x86/lib/Makefile           |  2 ++
 3 files changed, 16 insertions(+), 6 deletions(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index b0142e01002e3..ee5e6fd65bf1d 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -319,6 +319,10 @@ config GENERIC_ISA_DMA
 	def_bool y
 	depends on ISA_DMA_API
 
+config GENERIC_CSUM
+	bool
+	default y if KMSAN || KASAN
+
 config GENERIC_BUG
 	def_bool y
 	depends on BUG
diff --git a/arch/x86/include/asm/checksum.h b/arch/x86/include/asm/checksum.h
index bca625a60186c..6df6ece8a28ec 100644
--- a/arch/x86/include/asm/checksum.h
+++ b/arch/x86/include/asm/checksum.h
@@ -1,9 +1,13 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-#define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
-#define HAVE_CSUM_COPY_USER
-#define _HAVE_ARCH_CSUM_AND_COPY
-#ifdef CONFIG_X86_32
-# include <asm/checksum_32.h>
+#ifdef CONFIG_GENERIC_CSUM
+# include <asm-generic/checksum.h>
 #else
-# include <asm/checksum_64.h>
+# define  _HAVE_ARCH_COPY_AND_CSUM_FROM_USER 1
+# define HAVE_CSUM_COPY_USER
+# define _HAVE_ARCH_CSUM_AND_COPY
+# ifdef CONFIG_X86_32
+#  include <asm/checksum_32.h>
+# else
+#  include <asm/checksum_64.h>
+# endif
 #endif
diff --git a/arch/x86/lib/Makefile b/arch/x86/lib/Makefile
index f76747862bd2e..7ba5f61d72735 100644
--- a/arch/x86/lib/Makefile
+++ b/arch/x86/lib/Makefile
@@ -65,7 +65,9 @@ ifneq ($(CONFIG_X86_CMPXCHG64),y)
 endif
 else
         obj-y += iomap_copy_64.o
+ifneq ($(CONFIG_GENERIC_CSUM),y)
         lib-y += csum-partial_64.o csum-copy_64.o csum-wrappers_64.o
+endif
         lib-y += clear_page_64.o copy_page_64.o
         lib-y += memmove_64.o memset_64.o
         lib-y += copy_user_64.o
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-44-glider%40google.com.
