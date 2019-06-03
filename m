Return-Path: <kasan-dev+bncBDOILZ6ZXABBBWWI2PTQKGQE6NYVG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF11932BBA
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2019 11:11:54 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id r48sf26527622eda.11
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559553114; cv=pass;
        d=google.com; s=arc-20160816;
        b=fTvGWCO/HOqfcTa546zTNif63V0sQje+oZEENXS0AK0Rm0hHtZdo2iheHjUmjjzjB+
         R4YYuKJssjgJfn7npxlVZ6tK2uiUpHlfoFlzZ3iwRWSzBQVLOUMvel9PNDPtZj0xg5bm
         KTXuqhZkadUzypiZIDJ7Uc6vM8kUsW7syXFy2BRte+97Mvt4sub0s5RRyxHYczRGmZV1
         5u14k6ruFUTJjEiLZNMdnJ84QJjBheYNMupEslexkDQP36PNIzf4lifAzbJmqR2HeCol
         XJ/8z2X2MBHAUDwCYZlh3WWHLaH+8E+GmaaQ9yxm+GvZ8Z27uc9qUnoRTr0jffqbRyG3
         QD2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ngXeBH8HHZx7HFDUnF4yU35GRjGrfVNBFEm1NyWgPgI=;
        b=I6hkSuP9gaOlfkSGIHPK78SPxm4DAeCzbAKxP9x978KQgu/PyPR9qfApGXrulRR5Sb
         +d25mZgE/EMbREPhM0NesWsRdtxe2D0Q5msx2H/LmK4XXQATFqe+qMalfK8miSZv4kJk
         PUoBBSeyPaW0DQHFSl3Iqkcswk1NHJOBDWk0y5ypKKzLZHbLqfKVI0G7vJazoy4v8NpC
         /2TSM4gsR7x80p8AsZ+0RMTHRujop1oq+CWzMow6a3sUNlZUcb/xd3wvX5MhdEjkI6BM
         ZQ8U8VkPkRDlICw0zZ7q3JCpBnJLzJMm9c3TK+sVtCI/9Jx1qDyic/e0JmOqqXMmLq2Y
         UXdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=m8TntvGG;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ngXeBH8HHZx7HFDUnF4yU35GRjGrfVNBFEm1NyWgPgI=;
        b=Y0Uzjgy4CPcPhP2UQVZH2ovHgUXCt1bqBAm8h660MDFkxh+9zYnOExpkZ4vRMBL7oL
         kR+WieEpgWRatzvkAmkIvuzV7lI4COYKMoJ4fwYgDqFNOELNlM8T18DZRWI9u6dDpMGa
         tB3k3fJAYU7NYbftYTpquAEbPl3MNSxQNchBi1ieBVQDI+YIu4GlTrIQ5+sS+6Q4xrWP
         KGYF2YcxDUixKe5Uwn41h4OL77uPhlauMEPIERGoeLeifsOf5m+tvg+Q6zITHYT86clH
         bjwNfiaMdGbcrRxgtuCC9L6NtLHDcqFxPO6OnrQC8SmJpVg2VJFlstQt12dxKbUFkgT4
         QNPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ngXeBH8HHZx7HFDUnF4yU35GRjGrfVNBFEm1NyWgPgI=;
        b=iba04tBsdTz26GRF188g27vGLnTQKkruh5bKj8Bxrtwk8jhmcNP2Q17m29Gt9r6RmS
         qYnuonrjvLhedyzAz3zhOfpgn2H/gkvHvUwuslRHwFIU9trJ5dt2B54s+7DC2NItpzPQ
         lzdNhBRNXd8f42BhyDc9P1X+fDvDiaySd3qBZCEpgwKd3PYsfH0/1IwsIuJYPLx+3IlR
         lH4HxlbO9NqB5Pl4U2p/4n8vui7EoIBB97+cw47PN3uUimIib7d0UagNszdupzuOaCol
         gvX6lcEGnbeshKeRq16Cqe4lcCltun+U4iL+ijOcRhu7UOSkbn4H4bjA59jhptYhFxMu
         OQtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVFcTePmHtppocFvKOEu9j9/FNQtIpLfjYP8OQjP6UCX74N/LaT
	J+PzLU99Zshqz0jCN03ngQg=
X-Google-Smtp-Source: APXvYqxN4qJjpoRhOw04LWdH6yXDbNmKvYSsFJAJZ54YpJ5n8eWrMBRLBNvehgSZM/EmdldZiu+Q+A==
X-Received: by 2002:a05:6402:648:: with SMTP id u8mr27489733edx.176.1559553114755;
        Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8e91:: with SMTP id w17ls4567376edw.16.gmail; Mon, 03
 Jun 2019 02:11:54 -0700 (PDT)
X-Received: by 2002:aa7:c414:: with SMTP id j20mr27296623edq.64.1559553114380;
        Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559553114; cv=none;
        d=google.com; s=arc-20160816;
        b=jG0NHUf6lbU1OD/cn0nIvikVBKwJnjStTmDmGkIJ9tJphMiSjCH7JqIAOSU1IN3zxA
         Izib9tQoL53rJUhOqV0Tkxl/AzKL8IViBApJokSOMDz1L9o45fPgsdP0FTllR+STolxc
         0G6ax8ovSMwb/pmn7BqMPjZNlvU641YGRl+jinyGeTjd9i0zR3OxGfA9VdWuIFAVxa+6
         4GE7/7HXGlr4DVSmBJtyZkN9Q+Coss12KmNn6Eih8yFsjpkprK9KFH9i3A2NgeHKb6gb
         Cclrdsj6DO/iE4nNastQ6DYMDSUZ1xz+EG40uPGRqhv4cf0VaPNjr73tdkKtfGZeP+Z+
         x9QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5XNaoGruNIsOtSVFYVpHUufh5QsS/no9n1jDse4Rp8w=;
        b=QYtkKCbTsGtn1hC/GBrNlumTsZCWs39jiqbzwm/W3kPtU2mdWQU+kSaphG52h9IJBU
         juH83g7dGrePNEr4NkAZ+lgwyyQNAkKrg8cr/8Y3QqTyUNPkz9zyKvs6ozT6zPbhbyse
         ti9t4XTLlGMwYmX+OxsDlJz8VylAvjWTDOpM2TRoffQy1zJ1THGoxUQomLf9KhVVynIH
         4sXlZCz6isrmBRFCeXMh+hKm9sLjxVF+UbcNZ//ajAj1UR3C9hDAF4OLc1dEPX+wo37S
         1tiO553nBYVIOQY+cQ+SQ0sWoPK0iswcmmZCBG/ls0XBWLk20Agx+n4cG3HzGkf28DAx
         nEGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=m8TntvGG;
       spf=pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id a38si507801edd.3.2019.06.03.02.11.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of anders.roxell@linaro.org designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id j24so15460691ljg.1
        for <kasan-dev@googlegroups.com>; Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
X-Received: by 2002:a2e:984a:: with SMTP id e10mr5408494ljj.113.1559553114060;
        Mon, 03 Jun 2019 02:11:54 -0700 (PDT)
Received: from localhost (c-1c3670d5.07-21-73746f28.bbcust.telenor.se. [213.112.54.28])
        by smtp.gmail.com with ESMTPSA id y127sm3040022lff.34.2019.06.03.02.11.53
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 03 Jun 2019 02:11:53 -0700 (PDT)
From: Anders Roxell <anders.roxell@linaro.org>
To: aryabinin@virtuozzo.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	Anders Roxell <anders.roxell@linaro.org>
Subject: [PATCH] mm: kasan: mark file report so ftrace doesn't trace it
Date: Mon,  3 Jun 2019 11:11:48 +0200
Message-Id: <20190603091148.24898-1-anders.roxell@linaro.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: anders.roxell@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=m8TntvGG;       spf=pass
 (google.com: domain of anders.roxell@linaro.org designates
 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=anders.roxell@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

__kasan_report() triggers ftrace and the preempt_count() in ftrace
causes a call to __asan_load4(), breaking the circular dependency by
making report as no trace for ftrace.

Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
---
 mm/kasan/Makefile | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 08b43de2383b..2b2da731483c 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -3,12 +3,14 @@ KASAN_SANITIZE := n
 UBSAN_SANITIZE_common.o := n
 UBSAN_SANITIZE_generic.o := n
 UBSAN_SANITIZE_generic_report.o := n
+UBSAN_SANITIZE_report.o := n
 UBSAN_SANITIZE_tags.o := n
 KCOV_INSTRUMENT := n
 
 CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
@@ -17,6 +19,7 @@ CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
 CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190603091148.24898-1-anders.roxell%40linaro.org.
For more options, visit https://groups.google.com/d/optout.
