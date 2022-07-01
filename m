Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP4H7SKQMGQEIRQB6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id F072F56353E
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:03 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id b7-20020a056402350700b00435bd1c4523sf1896763edd.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685503; cv=pass;
        d=google.com; s=arc-20160816;
        b=U7A/fmgSVUPINTAc2WQXE+2iMGpH4gGF2nvqJiw+gVrGap9uvmrIfk2ozC1cvneA1K
         e/SvP9ZLx1l5tjJQNpCgxAJXVziREWkTBZD1OemcctezwIzi4si/KFOmtGVlgv4gvIqA
         sHr0R2O9UUxdYlIPYQ0fNl36RnAVwCVh1JciQlgOo+ZaWNr7yRruOsMj9iNinJhI7D0O
         MgwwGA8PSCkFpCPYDcoFU5Ovb/vXfWV2lf0T1AUA9c8DNqKuoYMk6xBn4UCaHToEnLiQ
         xTDQefvxO1bEWVFNRBZ88vK8FB2CA6gh/lB++ZCwZReUNjhi1Q+PuSrIn12nSIoVTClW
         YCpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mEfZ6zhZrzQamNeX4RUsWbMD+NzBSMstABVcJgkgJNE=;
        b=h9/zFMBVnetCgoOnqq4ku5o4D74UqJjduvIOu8e0UOLwKKyIJRz27bYIsgWokBVN3F
         Eb0BR8cFtLlfxPlMR9E12Hv73TQRIkOiiP8/ZrWX6zy6wjis3GOK8eWoBSFb7/kIkvQG
         jWrQP+cxarxTe7uR/7emD+qpm7j92X5fX41ee2i878Q8IQOY2Gu3w5XCKISExx/O4V4W
         fgX7hAqJnYa5N7PshEq9wLhuVJmJd79TCYZ0PGNhcFoamT6yuL4ZcZ6GG40kI+Ku68SI
         UAR6RvPpSENnq/3wJeKC8QGmNliqftg566d941BTKWo1iyT982VgV6bkvpl1mkjnxosn
         5MkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="SK4zuM/L";
       spf=pass (google.com: domain of 3vgo_ygykcd0fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3vgO_YgYKCd0FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mEfZ6zhZrzQamNeX4RUsWbMD+NzBSMstABVcJgkgJNE=;
        b=gsLGPB9ElTkwKIvllVh3P4TDFVcKu1gdgoI3FaB5+l65u4fzYrYLHdIkOXR2YsrKAo
         DbqnNEE98cVFQrPK9Dq8iWTnGYkE7d9X4XWZQFO1Mlws1s3INWESFutZz0gemy1BF6Le
         e8rdRYCoVWl3IYuqPIZin0ZIhwcFudwwpdIA+nhxAUh05PHJiFrTsg0dZ5het6XLj+6c
         ej32zkgPCiHsndAn4ysKN9PZlCige2PMO3ImPWVzaGj4QNDahRu3VCN8uq+xQ1xrA/1K
         TJw7A6SeR1xcUW/F7K6A6FZPv0cOunIbrnwDfzAUkVFH94TAEcmuOLcKmh+JrNwnnRql
         doZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mEfZ6zhZrzQamNeX4RUsWbMD+NzBSMstABVcJgkgJNE=;
        b=GRXBX1VEm39TXPBzEZ9TjFSZzgfDIRH0GGkaaItyi7FYtxyzxuUn9Z830UtQVZfDyP
         C3pdLV8hFpBuyFTeBp0fh18yQVMbAbfTFCws9EhC+em4uhJQX7Bzy7iFiK4Yj5V71D7c
         1o9FF7rjLw3L4AaKHTDaZK2E/H41zzYdFhfmNSk2yaa7+rsWvxFRuCXuzeqFByaXCRLp
         il3X/IVGIkQeDwSnTnSnUuZH1I5jDKiQJRsw7arw2e8usfKErqEovzBeekxDjqt/Ahb3
         t+NlkSRlM9OIEJZir6ZJ2+9KM2UX6WKN+CBAfOvy9/dB7vkPCpObcdHE9VubpkS4tLc2
         UMxA==
X-Gm-Message-State: AJIora9HkO/mGyWVEKVgjphZmqlLcNXl7zjLG9yt5l8HavSkFzVrADI/
	0gRJSMuy8+wF14ePkRoo2zc=
X-Google-Smtp-Source: AGRyM1uq0jNQh65cVtqkl5XENlzfStv91rRhOim5aVt8af2TdTjxDljCesbNYS/kXEIPNFQV9+Meqw==
X-Received: by 2002:a05:6402:908:b0:434:f9d9:3b18 with SMTP id g8-20020a056402090800b00434f9d93b18mr19483497edz.37.1656685503737;
        Fri, 01 Jul 2022 07:25:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:274c:b0:439:6b10:daa5 with SMTP id
 z12-20020a056402274c00b004396b10daa5ls371359edd.3.gmail; Fri, 01 Jul 2022
 07:25:02 -0700 (PDT)
X-Received: by 2002:a05:6402:27c8:b0:435:d40e:c648 with SMTP id c8-20020a05640227c800b00435d40ec648mr19333535ede.200.1656685502744;
        Fri, 01 Jul 2022 07:25:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685502; cv=none;
        d=google.com; s=arc-20160816;
        b=dzo/N4KkCwaffCNwpZo+tjKEse/XT/wSet+L4dqu9kiMveP+YkpbzjS4UsebdJW90N
         gMfBj2idPo6jl4Kf0DYA1bgd3j+r5CuMVLObCyZp4N+fFtXbJlNar++e+Fn0Phg2YmdA
         TUFts+7nDCYekwoPL2PmGkdiRHB1ECyI6YkDrg1tQErNe+HJ5splbTJ65Axcpl2Om/n8
         Pt0tGYJMd0dpGPw49w5VsKGJEPEqQ7C2ZTm0BHICUmIAYq/MYJEDTSRImpgl7DvIafE7
         44p5q/F9FswecFjclWgLgGqrAoWib68mTCfxQgHWUlH3ToHhBLNTNPdloLa/d7L5P1Tz
         9fRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7Mhpta8bleV/UMALfZOJOInTXQD6eorZ40ixMEZLH18=;
        b=0innMTmZrKKp7FubkvDYUoXDqNJ4ELAy8qpHLzr8SKey8ICPRJHvisaEHwDnrTezz/
         IsjF0fwwCWiFY4gU2Gym2tHHArxO9feGR8dStabUNwkAoNBvXZ1pVe28VKU66EWAHxGq
         gO/QDc2OnFgKHfDHiXc6uryRqeS65uiWWpheQP+l1ZKa2cgCcf2neMSrRCQwcag5b07A
         g7YShgUXedxKICSwzAQgqZIoy+L+vsufc+V5H0CYDi+TeRFfM/v8v4PtG4/XlbxsqNsc
         ROF0lpGL5Qpro3Jw/ZjqS/srsLvlbNoaRZy7qLH4AWxoHHtm1Oj8Z40maF0joc1n6zmz
         oxfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="SK4zuM/L";
       spf=pass (google.com: domain of 3vgo_ygykcd0fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3vgO_YgYKCd0FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id t1-20020a056402524100b0042d687c85d2si698406edd.0.2022.07.01.07.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vgo_ygykcd0fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id h16-20020a05640250d000b00435bab1a7b4so1894473edb.10
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:02 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6402:f29:b0:435:c108:58f2 with SMTP id
 i41-20020a0564020f2900b00435c10858f2mr19006559eda.401.1656685502496; Fri, 01
 Jul 2022 07:25:02 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:03 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-39-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 38/45] x86: kasan: kmsan: support CONFIG_GENERIC_CSUM on
 x86, enable it for KASAN/KMSAN
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="SK4zuM/L";       spf=pass
 (google.com: domain of 3vgo_ygykcd0fkhcdqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3vgO_YgYKCd0FKHCDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--glider.bounces.google.com;
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
index be0b95e51df66..4a5d0a0f54dea 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -324,6 +324,10 @@ config GENERIC_ISA_DMA
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-39-glider%40google.com.
