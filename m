Return-Path: <kasan-dev+bncBDX4HWEMTEBRBONEVT6QKGQEOVR2FUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A3D22AE325
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:42 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id s25sf5274869ljm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046842; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nj9oBTYa4eAuV54NzRVzSnRy6dMQ5YxEYAFhSBs2FF9/y/WoaomVWDg0Rerjx4Mkql
         Mi+2PRT4KGvVad9QS1CQaJSYbXAjfMMMIrlvro8sFT49Ncfl/GjINmVKNFVQpuHVGs+x
         wmFiCuhmrO0WrQUxQW2uyOWCR11Dth81V21S6+h6mbPDmFehWFOJI/+vBdacvK9zumXC
         xAskupxq0RJai8ZM5AyUjHVboqMmABIQl4rfwdrormLdiWJxNJMQRQczZE9hYfr27G8z
         o0nynkihsCk/uBO0vRvedAC1NTWf84sOLVuZB6v9tCrDzDOq92Ls+t2mxrhhlHZ8Tj+j
         oEPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dQGF7xmsLtlFSaxWdDR3ce8o8KtBP6gZTiKah4c65rg=;
        b=OBW2Qap7Mj3kg/wvnsqArBfLbd501FDMOecjSDmXTbvec4+7rIGuk6B9VAthmeI5eB
         hDlv4mY8XoTj2fnmL8xU0noXOuUyj6a1wUOCxZQ8eh5nTE7Im3NANTjSsAlFoocWtoIb
         VooH6muYs1mNczNzLi1+ZlSnX+4dKuLIU7p6I0STwqORYUQ+QStn3XjRqzN36ayRx6NU
         FFTRHiinObKM9+b6n1QiflOGOvXq5tan9l7j9xK5rIdocbCO1AiHNi1CaEFbCYVeVLuq
         P75zJwe1aXmk1S+b23UhgKWe2iy0BwfoAEOzhaBqs4VBZX/79LBncF4RHy2TMIMBlo3m
         Zg4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=anCq4Edn;
       spf=pass (google.com: domain of 3obkrxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3OBKrXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dQGF7xmsLtlFSaxWdDR3ce8o8KtBP6gZTiKah4c65rg=;
        b=Esp1pR/l3vBsvTdWWV/48l4LxZxIwUNbIFM3w18DJwtSCqmLh9VEupQJU9S66Ad1gL
         DPe+bbSPbpkFHc1kK5vvSxOWlbgFRPL+8EU2gb1x3bc4+NeezaXACiYZp1W3EKPTbjUd
         Itx9w2oUKwzUPfB4AvWnXFK4BCfsgVQld9Wdg73n4SQ0uTS3AE9qY2Qgiqt0nMtLr8Ib
         M+UAcQ8MV8TIAxM/uyNKOdai1wx4OOyIFssGP54HIxo8iH31/yfRGZWF5j5abEoM2axy
         8j7nLdQ4pn+DbsTOZwQcIhfRqiS77cQbramAflrKnQU3JP5mWrdz6ykxQ1qsnVGHYPa2
         Zckg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dQGF7xmsLtlFSaxWdDR3ce8o8KtBP6gZTiKah4c65rg=;
        b=IvsgspzeL1/ol0Iir/Mz2QrrCKn074nh8zHXCbgnxwsaHFfDGq+WKTgTv8pF/vv0AI
         ANqUxPDJ36K9J6XEcTc9L9BO+v9Qhi1QdmLGwN5W2FpwO8RBlNOUsEww2sv34y1LuanX
         Gc5bnjMQ+T84IKtZjQuOPkQPKRmjIBVyrVnAYUcq2zFpxQFoDmC9JW81ITKVQ1LpQXu1
         JAmir4Kw08aHhzABt3qtyDHNzAJEU9UfO1THICbCCh4Gy2jVqmkwVS24MzOr1l8bU6ln
         a3Nk8x7CHKqG5TmwgGsPWo6ZQHWObJ3nL7JyrmBamDSLrbZr0zc7sZHnkVGho2ap3Wan
         C2Zw==
X-Gm-Message-State: AOAM5316otySA+OJWKUssPTnXyB+tnhsN9sfZ/2YV1MQKpDOSuNRAVi3
	S8Zk0gthxBO9CVOak68UvEc=
X-Google-Smtp-Source: ABdhPJxE92U9lwzODXbf1mY7mMeUA+Mlvek0vXlndqOq+ombpfeCzf2mr5MFkMdUNeX+YmfXMm9I+Q==
X-Received: by 2002:a19:7e85:: with SMTP id z127mr8880938lfc.493.1605046842064;
        Tue, 10 Nov 2020 14:20:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:6b0b:: with SMTP id d11ls1296266lfa.1.gmail; Tue, 10 Nov
 2020 14:20:41 -0800 (PST)
X-Received: by 2002:a05:6512:2151:: with SMTP id s17mr3926837lfr.287.1605046841188;
        Tue, 10 Nov 2020 14:20:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046841; cv=none;
        d=google.com; s=arc-20160816;
        b=PtzojRNKNt/gxWltRtCMSKVdvMidOFLvgS64Mc8ghNvSYbM6JvN7Wfaf26FG1bd0Wm
         5C0wfF9h95MIHR1p0ODvL8dnW68zpYtXeYrsp5sAm2tUJpdiZ60JFJ3u6yzy1wFMdcwm
         OCgnhoSWXA/eLGfM7MiDG6bMxbHHnfto62YmrVDCKdhwO/YMHRwYw1plnkh4VD73pKDz
         ++1ST1ldegmsYCFBpVvL9X4j0GrbH8EIE9/e0DkB8t65ED3LdtBfwBcXaV9hnk5h/yFz
         Ms7XruN5PZxJBzXOPGY5W/ZS/Kcaal6ok9b30mf/xbRffvIwwF+a/d3QMkxle6GrLpcD
         LjUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=iclGPRxOEu/Y72cezYx1VmP9mDKpdmhcr9SlAN2oUkA=;
        b=0Ff8W2cAeGTAikGIgmtQwhJq4Lvrkscrg/54WH8r2/s6BT7sxFGbBI6Mu70IxcpKGY
         4kt+V9vZKyxrQ6/y8ZN1Dju9bHFdyQUW2GOcNwk2Iv4x4uuYXKLrBKtHqCgl/V6pDQh0
         BiyZfnXyTy/3Z7jsGd80OJcXQCNN66AqRo3WmOiuoZfrPh8BDVgxVxTRoLRH6qREfUX8
         NCYJx0Oy8ryaixJbjfgJMSyLTWust2CgZ4tHWjMcxJvOYJA1ewAPb/ZtcEJICyTSzmWZ
         PnnuU2YX7K09TGOmYS83T1AR7hvuYFKJg7TrcC6cFk1CMPH18D8c6+YENyYz1K3w8cox
         RzPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=anCq4Edn;
       spf=pass (google.com: domain of 3obkrxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3OBKrXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id y84si4298lfa.6.2020.11.10.14.20.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3obkrxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id r6so87874lfc.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:41 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a2e:320c:: with SMTP id
 y12mr9612197ljy.362.1605046840773; Tue, 10 Nov 2020 14:20:40 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:09 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 05/20] kasan: allow VMAP_STACK for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=anCq4Edn;       spf=pass
 (google.com: domain of 3obkrxwokcq0n0q4rbx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3OBKrXwoKCQ0n0q4rBx08yt11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Even though hardware tag-based mode currently doesn't support checking
vmalloc allocations, it doesn't use shadow memory and works with
VMAP_STACK as is. Change VMAP_STACK definition accordingly.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
---
 arch/Kconfig | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 56b6ccc0e32d..7e7d14fae568 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -914,16 +914,16 @@ config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
 	depends on HAVE_ARCH_VMAP_STACK
-	depends on !KASAN || KASAN_VMALLOC
+	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
 	help
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
 	  caught immediately rather than causing difficult-to-diagnose
 	  corruption.
 
-	  To use this with KASAN, the architecture must support backing
-	  virtual mappings with real shadow memory, and KASAN_VMALLOC must
-	  be enabled.
+	  To use this with software KASAN modes, the architecture must support
+	  backing virtual mappings with real shadow memory, and KASAN_VMALLOC
+	  must be enabled.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl%40google.com.
