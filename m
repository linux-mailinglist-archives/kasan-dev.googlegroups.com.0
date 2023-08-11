Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKND3GTAMGQE6WTLUTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C8987792D7
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 17:20:10 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2ba37b5519fsf22798001fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 08:20:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691767210; cv=pass;
        d=google.com; s=arc-20160816;
        b=kOBeKmJWixWUR90CoWGH8bmXjTiIyLORvau3Q42qaf8FcjgfrJvYU9a+Fnjg7so9OR
         C6wAcvFKTpG9NUEvidfO7t/Yr1k1ds1biP2n49xbhUwhjlAIOUJ7i2UFm5ViZbD9W5hZ
         PlEvcSIo7J8b+Y/wmHbKbBDXatdAy1a9eerd2g9t2fdDEpOn7rdWxPmehKAoN/4WY5Yx
         lQobTYQbjdlCtI8J4pINNTy5N6SZMyBQ2Mc34dOzdV1HrvWyXxeee3hLz7xa0rckR4A2
         dDL1cf50agJl0oo03zrgQKsypuKWdQSRpXE8sIbmJqXcBtCD5y3d4VNlOfAYToz2Lmgm
         gAxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=eYBMjUo2sSbojXaeTg/t7AS2Nb8kE4My/5laMHNNuWI=;
        fh=qzUwxS9h9GHZXLKRdSveNA0UW/h6SdpMH03X1Oyv03c=;
        b=GOfNSfAU67oUQVRtxoz4OBcBWcfBHO+M6jiDUduF3lVoLwce2AJnDO1RfYZeuGrT1Q
         QrVTs9/uAolrSlxBmj2JdyFgwosE9RmYAA6pm4qSTDLuVhLvl0pLzaHnc1VmlH6MMngH
         17UedwKWlrm2cKBr2IIW4GwUwT+ed54W8CVm0vTG8+diU/TdOQP8KOCrnx5EbHehKFWA
         AWeHHMUH9oqGi9FG8TaZg5U7wicoMVDMHM4Gw0yMf3/2+T9IK9kD64StJn9Su8kXyRCJ
         C1muvCitGHLPv/UgJUVaqq+9wajxFSnFHIFw/Ib4QX301UWWI2CoPrudw/om3r1NYh4B
         0jvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=10PLZEHN;
       spf=pass (google.com: domain of 3plhwzaukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3plHWZAUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691767210; x=1692372010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eYBMjUo2sSbojXaeTg/t7AS2Nb8kE4My/5laMHNNuWI=;
        b=HlWkxyexvxEfTqQsFIZIkElhBKOuJIiNsdZf0bGMyPLl2ZjtJn67ZQaF0XAfyH6w4C
         RRSMZdU38QpxObqiK7FWrU/4VkNwkGoSJx5iiG/fG1PeNeMoge16V2/MOR06Qqn3YckM
         8Cj7GJrTQvAaTtoq3PtUurwPAfA278iza8/3f9XwFnFoM/wwVvhtLakw7OHL/NDE3fOO
         p5N0BVknFK6L2oh8zM3GXhJvluDFDafVA2stmXbbUiWvETmNU84HM/CdMsZKssi9UtOG
         YFnxV0dLYg4nW+71UX6fvMeKsQy3g4LHNwar7qpyBU9gTDtJlD5ayc+2Fd1Q59yN7DK9
         h5AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691767210; x=1692372010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eYBMjUo2sSbojXaeTg/t7AS2Nb8kE4My/5laMHNNuWI=;
        b=TEjOpRkqou0+EHHBtp7ZrmugU8YsB5JwFiVwz6ms9Sac8FS/BfHf1WKPFw5NJygxxt
         P9A1rCRCIeAziDU6mqxDa+b9gWbBhuAiDM/NCUkF4n5FhtvigFlJJW8Ewhy+taIHhGqW
         GjfJ25lhFU+VFLygnCKJJa80J4qjfoq7R2Kt90R8B4NuifVtjKhPArJ5laAmRKxx4HiX
         C16PUj3ioJ/jBq7ZQqoldiH+bbucc12ERZiJoo+gGVF3tYx1YFIb9Ipm07q8xfyW7ODY
         WqxLVq7qDHpKK+vyXH5Te7nnkInH+47diF/n+yi+Cfcx1qs+7pZM24Gji1e97Enm/Uk7
         69Ew==
X-Gm-Message-State: AOJu0Yy1kaMaUqGlq/1fdUiAcs3El4Y/8+9PvZCd4EWsxEJt4rtQB2Zm
	gPx4jl2EHbFaBr86H/FSbvE=
X-Google-Smtp-Source: AGHT+IEQWD3UMuy7d9H288rvvef6oScU28uHERP41H3XHh7FEx5W5kLP8ZWuJWdRMyIjRijLpyQDhQ==
X-Received: by 2002:a2e:87ce:0:b0:2b6:df23:2117 with SMTP id v14-20020a2e87ce000000b002b6df232117mr2022602ljj.43.1691767209336;
        Fri, 11 Aug 2023 08:20:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7d6:0:b0:2b9:b171:d776 with SMTP id x22-20020a2ea7d6000000b002b9b171d776ls219092ljp.2.-pod-prod-04-eu;
 Fri, 11 Aug 2023 08:20:07 -0700 (PDT)
X-Received: by 2002:a2e:9a89:0:b0:2b6:d8d5:15b1 with SMTP id p9-20020a2e9a89000000b002b6d8d515b1mr1674068lji.50.1691767207030;
        Fri, 11 Aug 2023 08:20:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691767206; cv=none;
        d=google.com; s=arc-20160816;
        b=NoMrCwl3MemAk6c++0iLXhvSCUOk3N4AwjBjZlDl2eg767faCo7qFS5AOkkJ23eSw5
         Tkrzf6Y20hHo0O2cOsAtt60XAIyUaYMN/2yhaedJ08jLNIlZFH13yhcBZwnH2gZM4z51
         0EhvqFwRNDdW4JUIIktLvm4HA2y/PLH64pyjPsVpmefZaCmAnkibMey2nGBlpdoCWxou
         hGNgGNIoDlaGeCJUBYSgVnnc7UxHoUgrzLff0mZ7fC5du/8JqCNfQLmK69/j3wmNDtH4
         XDz4NYsDz3A68POInvNu+IlV+mkMZYLIh3eza2ZwSRHaqK3PkmaCkF9Td6F5lKBmow52
         kYhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=qzePDYsycDhwr+IPrP4iKR8Awa/mk+LR9zGcfd9N2nE=;
        fh=xh/g7dNJbwYr9WVB3rCguj1R0VLL65UcAaOvl7LeWOQ=;
        b=CxwPUvCgdG6QS1d6LMHqdOL+WiOg/C3IKbCeSfXzuEdFfE6DXhSZZjWopLO2bP5tf+
         ZEkIZTK+yYtiDLt50wwFSHm0kZz2WXX99iKuGg/Q/TNQdi1/L8TTRt2NMzghCBV95k75
         MzwKgJxpPhqkuOLcpJUPoT8KyK5tqz4TH3zR91UnQ4bvKLXjSLrKJGQyVS4Iv88ADPCC
         RCAb1/jgt45DT3dBSTPjw81RR+9dXMeS8Wozrk2eJd8lS1ims0JTFTYvSE9Hw7v9ZyGz
         wYKR+gQexze0I03qVemoGdQgTPFqVLApFD4qrWlFx1gh3o2VjUVSnQnMiZIckayxl9hh
         x57Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=10PLZEHN;
       spf=pass (google.com: domain of 3plhwzaukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3plHWZAUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d16-20020a05600c34d000b003fbf22a6ddcsi400996wmq.1.2023.08.11.08.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Aug 2023 08:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3plhwzaukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-319652e9920so83928f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Aug 2023 08:20:06 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:8dc0:5176:6fda:46a0])
 (user=elver job=sendgmr) by 2002:a05:6000:1819:b0:317:41be:d871 with SMTP id
 m25-20020a056000181900b0031741bed871mr16440wrh.14.1691767206297; Fri, 11 Aug
 2023 08:20:06 -0700 (PDT)
Date: Fri, 11 Aug 2023 17:18:41 +0200
In-Reply-To: <20230811151847.1594958-1-elver@google.com>
Mime-Version: 1.0
References: <20230811151847.1594958-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.694.ge786442a9b-goog
Message-ID: <20230811151847.1594958-4-elver@google.com>
Subject: [PATCH v4 4/4] hardening: Move BUG_ON_DATA_CORRUPTION to hardening options
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Paul Moore <paul@paul-moore.com>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-security-module@vger.kernel.org, 
	llvm@lists.linux.dev, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=10PLZEHN;       spf=pass
 (google.com: domain of 3plhwzaukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3plHWZAUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

BUG_ON_DATA_CORRUPTION is turning detected corruptions of list data
structures from WARNings into BUGs. This can be useful to stop further
corruptions or even exploitation attempts.

However, the option has less to do with debugging than with hardening.
With the introduction of LIST_HARDENED, it makes more sense to move it
to the hardening options, where it selects LIST_HARDENED instead.

Without this change, combining BUG_ON_DATA_CORRUPTION with LIST_HARDENED
alone wouldn't be possible, because DEBUG_LIST would always be selected
by BUG_ON_DATA_CORRUPTION.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* New patch, after LIST_HARDENED was made independent of DEBUG_LIST, and
  now DEBUG_LIST depends on LIST_HARDENED.
---
 lib/Kconfig.debug          | 12 +-----------
 security/Kconfig.hardening | 10 ++++++++++
 2 files changed, 11 insertions(+), 11 deletions(-)

diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index c38745ad46eb..c7348d1fabe5 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1673,7 +1673,7 @@ menu "Debug kernel data structures"
 
 config DEBUG_LIST
 	bool "Debug linked list manipulation"
-	depends on DEBUG_KERNEL || BUG_ON_DATA_CORRUPTION
+	depends on DEBUG_KERNEL
 	select LIST_HARDENED
 	help
 	  Enable this to turn on extended checks in the linked-list walking
@@ -1715,16 +1715,6 @@ config DEBUG_NOTIFIERS
 	  This is a relatively cheap check but if you care about maximum
 	  performance, say N.
 
-config BUG_ON_DATA_CORRUPTION
-	bool "Trigger a BUG when data corruption is detected"
-	select DEBUG_LIST
-	help
-	  Select this option if the kernel should BUG when it encounters
-	  data corruption in kernel memory structures when they get checked
-	  for validity.
-
-	  If unsure, say N.
-
 config DEBUG_MAPLE_TREE
 	bool "Debug maple trees"
 	depends on DEBUG_KERNEL
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index ffc3c702b461..2cff851ebfd7 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -290,6 +290,16 @@ config LIST_HARDENED
 
 	  If unsure, say N.
 
+config BUG_ON_DATA_CORRUPTION
+	bool "Trigger a BUG when data corruption is detected"
+	select LIST_HARDENED
+	help
+	  Select this option if the kernel should BUG when it encounters
+	  data corruption in kernel memory structures when they get checked
+	  for validity.
+
+	  If unsure, say N.
+
 endmenu
 
 config CC_HAS_RANDSTRUCT
-- 
2.41.0.694.ge786442a9b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230811151847.1594958-4-elver%40google.com.
