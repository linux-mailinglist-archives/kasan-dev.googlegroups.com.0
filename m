Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5HVZSQAMGQE3ROHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E82366BD456
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 16:51:17 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id c29-20020a056512239d00b004e83ed6bbc5sf947126lfv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 08:51:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678981877; cv=pass;
        d=google.com; s=arc-20160816;
        b=AneQqzJUTDQuFcburwxx10Z6q0xEtQjW8+/wSHZIhNBFC4Yn7aguiGx2J3ycKXQs+N
         BtHmEeqvLm46irqdg0bw341qdg1GEFCwxG87+ea85mqNczShAGfKn5MnVEzAYTAmMmRA
         yPBBXGZkevJP6trl/g9Rmahoiuzf7XtquJ4ok2WlKZFeGmeZvYaEVXyPJSI0aaPSeu+u
         mQz4TI8AuL8GAGShO1SgjFPxv5GCbm4cJhZz39NYKeHgum6gWO/N/bHP/hyRAEp3SKXP
         xKdgrrOMkyqfa5QFOH5vYZARw++Au3/HuDeSoO4DOgOPLGgpDBlkoBpPAmP1M7g8Uq3U
         57qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=1joJXsZ6Zmv58xgqVNHBzWVoj5liCyK8u4IVQ8P2Km4=;
        b=tASxaFZON8VSE0U1ajFWy8OWI4gNacGD2R9EoDz15wqViD1oFc5Tfc9OXwNRqNQhb3
         SmbYzmB1a0VeZV+wGuzbquV3nImEMesGrgaYnqm6c6OIE3NnrxZ119t1xJrzNuduqTWZ
         721roRXvjTddW5qPrPWy+D5NBTFpNVdxS4Vvcntf6zx2qyvj5YvrzQBcCNnxPgAf2ayO
         v/lULwb6ArHwViC3iZgWFh7vcPOD1cyxf/SOwcEsiM9SMh4Nxf+kOQcMcn2SpJc1YMa0
         MYXkDaXkr839lBW4TGLddbHwRDR8feVxXw4wr3X4W5GrpqJ110deIVY6JDOf2zlVPxz5
         aM9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BaozqFKk;
       spf=pass (google.com: domain of 38jotzaukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38joTZAUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678981877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1joJXsZ6Zmv58xgqVNHBzWVoj5liCyK8u4IVQ8P2Km4=;
        b=eugRIYrdw9wkfXSjIsPmkTKxFAkWkMQXFgBm2swMwoFWsQ7+EjZtfcpuvryo4P3PzB
         mkIHqBBWfvX6oHzZWuediBfpbtl7hQzXym4FhNmj+Q/l1mlcLoVE7LOdZxlH4M2iiXdK
         /+4Xyz6VK3KsZaRDCHZqh7iNfXyuhe0IZX+ya5YmMhAarltphp/qKZsTH2R55SpgVD56
         gxcXk6itATWP3Wm/M7Nz8Khu4GDQICKeKlpHbpYWYCOR8noi3WybTGqe0jYjgSv6h+5I
         quOoi7WcLKQgRXZ8DB1bfjLeYG/erQwQczobOr/Iv2Srh+pWcuz+RooHEK/c4aI6ok77
         yAtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678981877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1joJXsZ6Zmv58xgqVNHBzWVoj5liCyK8u4IVQ8P2Km4=;
        b=f9UAzGe/o1+L8kQBbkEo2IeeMKzhHhi4NXrtYuB7XKWMiHLU/oN0UV1PHNMMbL4hFe
         ij4HYEcA583Fv5WfoP6npi5hBmz+/gJ3kF5YRJJg3Knk42RcjXZ6qoBQYuLlTTGAPY9G
         hIuK17g2KMlJvbzo2ip66R0YgOe/NsiX4S7q+/mTYndwjWslCEqju07dYTcq+xnXCdQU
         LSjCidRb+m8gT9IZt6O7lMNQZcnlrka5WSHnEgdwLpeOBn6vQ+hiwTLISPS0vN1HV1oc
         pMi6j8QE+LtK9Kv0gReSyEnplSfECeHZQBxn95a2sUeLQQi32Z5Gmxn573QGzHMBsk/W
         RfiQ==
X-Gm-Message-State: AO0yUKXZtEtTLQPcqqfrRqpQCcrsjnHu1So0Wu3J0DyOq2yv6drsqXBA
	N00Ez7Vqdq6ZA8nYS1LSVcE=
X-Google-Smtp-Source: AK7set+Em/k6XarHWK2vuWahthEcyRtVuAe3shkkMu6tDA5prYkc6CAbSf2bzf1UmjPYSBFDH8stTQ==
X-Received: by 2002:ac2:43d4:0:b0:4e0:822f:9500 with SMTP id u20-20020ac243d4000000b004e0822f9500mr3345170lfl.12.1678981876977;
        Thu, 16 Mar 2023 08:51:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c6:b0:4e8:c8b4:347a with SMTP id
 k6-20020a05651239c600b004e8c8b4347als1881774lfu.1.-pod-prod-gmail; Thu, 16
 Mar 2023 08:51:15 -0700 (PDT)
X-Received: by 2002:ac2:5084:0:b0:4c0:2ddc:4559 with SMTP id f4-20020ac25084000000b004c02ddc4559mr3091227lfm.69.1678981875269;
        Thu, 16 Mar 2023 08:51:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678981875; cv=none;
        d=google.com; s=arc-20160816;
        b=KrL2Q/4kr6w86mxiZ8JlJCOU5V7MksggaRdiEvG8XAaFvS4NJAkLbS48i5yc+zUJNG
         83N5nO1aN9iFO8ttGgBp4mZnTo15evtHGN6MiLf6LUfj2J/Taz1FJVgmcqDX55faJrvt
         dZF6VG9zFgkrbz+rjQ7fl3PSLZ12MCTrTe7ynDKNOfXz6qslBS6v47i2sRQKck8bBeO2
         i1aogKbI9KOq9kD+z/w4EcjATyJwbKjyDjmaWgS+7HmORckOOLVmiFa2eFFK/fZDmady
         tGC/G+M11uLvzym77OqUWNGcxvlOY+eFmAsBqLDdM7lMmUV+YA8yF8RI+6Xfq/J+fGg4
         GIGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=ExLMwJzNgwWRHjnTjtALJSPVKx9BbSWtrYmWXQLM/Bk=;
        b=GBKXVSJh3P38DPgI8CMdIpL7E70MsjtG1wbu9YAP1AoFw9ZOIMvjbI0dGTMRyb/OJr
         w1T6BEhFIvDYqxogSunpDYuUTWWZz2Q/h1ij4Vp77XD1L2U2At+xWXYJ40elAJUM0PKI
         6826jEtKtG4D4xR+ydsPL2JV9l4MjId2SwHJVaDaqTa1jsr7+IfB+v0oj7JyW60/MYQh
         6dWjHEPFzwxjmSTiNZnDY81+NuT+6mqpqFnF3Db/JCAD3hRmTBpZAZfS36nxWAXDfgWe
         qcZZar5Owiq0g0N/yzLTqghLYJutqYPRxSQT7puyDfAFE9qJxNo/4X72EKPr3E1kklxc
         kisA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BaozqFKk;
       spf=pass (google.com: domain of 38jotzaukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38joTZAUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id a25-20020a05651c211900b002934b9b1f69si436057ljq.4.2023.03.16.08.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 08:51:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38jotzaukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id er23-20020a056402449700b004fed949f808so3663033edb.20
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 08:51:15 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
 (user=elver job=sendgmr) by 2002:a50:ce1a:0:b0:4bb:e549:a2ad with SMTP id
 y26-20020a50ce1a000000b004bbe549a2admr43911edi.4.1678981874737; Thu, 16 Mar
 2023 08:51:14 -0700 (PDT)
Date: Thu, 16 Mar 2023 16:51:04 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230316155104.594662-1-elver@google.com>
Subject: [PATCH] kfence, kcsan: avoid passing -g for tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Nathan Chancellor <nathan@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BaozqFKk;       spf=pass
 (google.com: domain of 38jotzaukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=38joTZAUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Nathan reported that when building with GNU as and a version of clang
that defaults to DWARF5:

  $ make -skj"$(nproc)" ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu- \
			LLVM=1 LLVM_IAS=0 O=build \
			mrproper allmodconfig mm/kfence/kfence_test.o
  /tmp/kfence_test-08a0a0.s: Assembler messages:
  /tmp/kfence_test-08a0a0.s:14627: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14628: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14632: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14633: Error: non-constant .uleb128 is not supported
  /tmp/kfence_test-08a0a0.s:14639: Error: non-constant .uleb128 is not supported
  ...

This is because `-g` defaults to the compiler debug info default. If the
assembler does not support some of the directives used, the above errors
occur. To fix, remove the explicit passing of `-g`.

All these tests want is that stack traces print valid function names,
and debug info is not required for that. I currently cannot recall why I
added the explicit `-g`.

Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile | 2 +-
 mm/kfence/Makefile    | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 8cf70f068d92..a45f3dfc8d14 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -16,6 +16,6 @@ obj-y := core.o debugfs.o report.o
 KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
-CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
+CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -fno-omit-frame-pointer
 CFLAGS_kcsan_test.o += $(DISABLE_STRUCTLEAK_PLUGIN)
 obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
diff --git a/mm/kfence/Makefile b/mm/kfence/Makefile
index 0bb95728a784..2de2a58d11a1 100644
--- a/mm/kfence/Makefile
+++ b/mm/kfence/Makefile
@@ -2,5 +2,5 @@
 
 obj-y := core.o report.o
 
-CFLAGS_kfence_test.o := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls
+CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
 obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316155104.594662-1-elver%40google.com.
