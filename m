Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM5NVCXAMGQEDD232OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id E6D748513FA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:01:42 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1d93f4aad50sf4515315ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 05:01:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707742901; cv=pass;
        d=google.com; s=arc-20160816;
        b=gioATX4ZlfB4DOeZfjObE9mLCm9iy/QZbxPV3kDOlybjPdNbxoQNklUZSY1Au5kukH
         qV+Ej9HJtn2HAix5XpqJnhIW3X5nMSGfU4DrRjMYOGGzfiLgPyhRgfXBcBV98ZDd68YJ
         yHpFztk8tAHLKlrDErmN79O6zTumi/LQkb0Ityoe1eORbrVlcy6w7fqIB9N+tgjCn/Sg
         m5myG4186Oprbtd0KPzu9G+qeauUVCHDstyP9qZ633/5WEYrKEDYWV5yuvdbwLeY3b7D
         +NXXRENG5gqQhXxYXyElOGVgJx00TADhAvvDO/pTRWa/7BbSAIFtB8/208gDyY5tV8mi
         rXPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=15yWwz/RoYb9f/YjMPKM9RcIuGN1G5dAW0Nd6xze91A=;
        fh=uRLcu89sK0H7/RvhAXbGxZWAbFNtoumqxo9XqSvjQ8M=;
        b=hmad/PINKVaQ7Iv6A09feawoBQvO+kjJMxWnA81e/hhMg0FnO52/hoX1eo8cOCfJda
         xTet9SQdBls7uiFLxCzmhWEiYFl6UmFOh82hrkZBicSLTd3+bO6X42I3QiC39BEVIQzz
         4qdEOHoHkNzVW+mF4HR9FhfxuwOg+ypnM4EcWdec8I/y8dyhjpaTIJ49wcsUOo4Xv2CS
         L0TfdRCwccF0tH7pHyfnGE2mc12tgJtRsZkOI5VZvhOI1VT+mbxrcqecfgRZFFoHN/xU
         eyjbQV8lr3TGTbz7IGI+LCcxVfmMmrOfR7hARGCZfyGgMlhRvcKToACU7qX77+jT1LkX
         I9Cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pVn8oxLt;
       spf=pass (google.com: domain of 3srbkzqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sRbKZQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707742901; x=1708347701; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=15yWwz/RoYb9f/YjMPKM9RcIuGN1G5dAW0Nd6xze91A=;
        b=Mf2wKkgvH5px/SFBxLNoQStAaTwfQa/PcfnbMg7xz/QZ+lmtYtbMgS4P/0KJiFubHj
         1ayGLtXNhI/Wdt0hKsXxZLWOkfQVrscLjRSi5n9TQkRYkVmRpCx36nQMM2hb0l7dWvAZ
         LTCx6uGMvQ/d2PYzOQhvp4eXb3sdrq3IRyDu1zujCkMBRvhJnPl+y0ALR1n5LUNBa85r
         NvnT3PYNLpH5AZWbDatdhLtdypd4YMpHmQgTshg6F5qHMWNX/tYT3AGdg1aSTAruEKQ6
         ubi6Cdc9Obr1jDteWee5jVLWYGeVlMmM1jmsHCeGHxpDJR36FPwN8q34GJssKdNTdk03
         l42w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707742901; x=1708347701;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=15yWwz/RoYb9f/YjMPKM9RcIuGN1G5dAW0Nd6xze91A=;
        b=s+YTZQemPgx7hhTPJVcyypeSIdrOwbtKUehqLBgZ1Fs19LUEWXc4JrSMBIF9Hw1sN5
         to4FgXypvOG/SNX1yCBcY/Pa9xBYLMxcNNU3/0ZPW0d4uG9S26HU8DoMjDY5KYPTq/jW
         V25hwjahAkJ8DUkK6ldcl1H/onrSTxUYs4VkpgDWe+JqltgouaQkwFCoS30ugx0efe2a
         sKVAynWmlN5WihFxd6vatyPescL6T0utiFigH6xJqKnDkdi+2vCWMdI7aL0YoQ6zFbSH
         zmnyMp2fWfgQoBZKgHV0BwSPsIgezZtMqrfAGtK1VLZWbHEE7IOCfK305uuNsbLQAsuA
         T2Vg==
X-Forwarded-Encrypted: i=2; AJvYcCX/EiXe7GRphffn2MJMeTFMaHxovK/Gc8DBWrNiIljsH2FQbQqxFjzNp4GGhEyMAdEHCkLVyHf8JRDNwTreNAP++dTMZUtSSA==
X-Gm-Message-State: AOJu0YwRq7okWALXmy5fB+SzBo1s8YDtrHqMRxgqivYdwHeyBK9HqOEx
	KUJpC/9LTej2322oSwwXRl1FmXeEvdAE9lrHGLoMBEiTBVi8T5fK
X-Google-Smtp-Source: AGHT+IGCwdwBeE89RGoSkGS8tUnoA6pYwHj1Fa6LFBHUwAUcVYPaIt3PcaHz2f7jmI10waNNGa8BzA==
X-Received: by 2002:a17:902:e18c:b0:1d8:cc74:b11e with SMTP id y12-20020a170902e18c00b001d8cc74b11emr264609pla.6.1707742899689;
        Mon, 12 Feb 2024 05:01:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e555:b0:297:155e:ea69 with SMTP id
 ei21-20020a17090ae55500b00297155eea69ls1382035pjb.2.-pod-prod-03-us; Mon, 12
 Feb 2024 05:01:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXyTi0hnu+8cqWL1tUq5zZvPPcue3tK+UXQWmYODgG+KwVW5alSmFkeWpyi50w2S8s8Tatj+kYGSJdOUjtH24LPIJIqFlT1cLS0mA==
X-Received: by 2002:a17:90b:1190:b0:296:84e1:de64 with SMTP id gk16-20020a17090b119000b0029684e1de64mr4669510pjb.20.1707742898120;
        Mon, 12 Feb 2024 05:01:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707742898; cv=none;
        d=google.com; s=arc-20160816;
        b=FXfSme3xyiLjRwnb6EuhT9HAWZfwz+ASt3H2laq/Ii8CDQSwsIkKMlw6tlsyK5gV+m
         ZwLdhOBaSjQADKNa4M+NHyWrsuHOsxf5KzaR2rTKrv0lYNRPfhT2oGAwZj9F8ZTd8Jm/
         4Q5CP2UtcRrA54k3zx04ol/VgsME/tsFhbkLkODugNBKg18EQioiUHcVdqs7LajD3+u5
         Xe0iSI4/cklmuqNlOzVYswjQgmlcDjosXwjAt+R1dMyb1SA84nd5YkCR9ctcBEZ8PL46
         enfl3nVYUVDUI+7d0tXt5KRjbxozUyf6qeYpdL7AuDR1/h9RsbrtoxDhPUcx+mjKisYK
         3uyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=pdujWWnO8d2IohPiw763CkbnCFmrIW28np/fZXta7cg=;
        fh=DTcwNLjeWmv0fSpFMa3qMSI3tY7sp3poO0qbcI4CgiU=;
        b=siyKFOvjzm/hN3Us3FeI1NmJv1C7sL3FYyDdtHhnHAHLtnyfjeeP1ePaORGEzD+pNv
         mHDjx1CbZMWoN30XSsB3GQu+gCmbBr9VouavTa7NEYavzYgD18biNqj0IatRUr8AQL3t
         rZA7fwMuOtGcFVTlxuZr739WUKZMCSVZp9m1JyYYPr3sfKzN4Hiv/5QVWYsfo8+sqVAW
         SnJuOSbHnXcNifJKDvJ0os/EeqhV+PCHjUkuvJC7dG4yNhBJkAlbwAn39/4f1dmux0rM
         xjgMbqa+N5v1lwq8gppP4N5WoRgKNO3tEqPLzNP7fmG6fp7yr+yHex7KDaiBNsS9QRCi
         Snjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pVn8oxLt;
       spf=pass (google.com: domain of 3srbkzqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sRbKZQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCUWaoUGakxLcjV6i5u7idfAh3n4P4AxynDEyJlxaSJYdFKWY48gbd47aA73WojDzs2cD0DLEejcKjJ5VHlYHiqdkzG8jSHOuiTq3w==
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id h19-20020a17090acf1300b002961982cd88si33336pju.0.2024.02.12.05.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 05:01:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3srbkzqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b269686aso5031804276.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 05:01:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVpbF2oPD1YovO1JuZoMoijHRLu5CZLOANo3Yj7D0CuSvRI9RDprk29GqaP3eF3HdT/2UzGIbK099Y5wVJypED8JeIWWZ4Ie+3UJg==
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:d6c8:d450:ebb5:bf7b])
 (user=elver job=sendgmr) by 2002:a05:6902:188e:b0:dc6:b768:2994 with SMTP id
 cj14-20020a056902188e00b00dc6b7682994mr196715ybb.0.1707742897343; Mon, 12 Feb
 2024 05:01:37 -0800 (PST)
Date: Mon, 12 Feb 2024 14:01:09 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212130116.997627-1-elver@google.com>
Subject: [PATCH] hardening: Enable KFENCE in the hardening config
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Kees Cook <keescook@chromium.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>, linux-hardening@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Matthieu Baerts <matttbe@kernel.org>, Jakub Kicinski <kuba@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pVn8oxLt;       spf=pass
 (google.com: domain of 3srbkzqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3sRbKZQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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

KFENCE is not a security mitigation mechanism (due to sampling), but has
the performance characteristics of unintrusive hardening techniques.
When used at scale, however, it improves overall security by allowing
kernel developers to detect heap memory-safety bugs cheaply.

Link: https://lkml.kernel.org/r/79B9A832-B3DE-4229-9D87-748B2CFB7D12@kernel.org
Cc: Matthieu Baerts <matttbe@kernel.org>
Cc: Jakub Kicinski <kuba@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/configs/hardening.config | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index 95a400f042b1..79c865bfb116 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -46,6 +46,9 @@ CONFIG_UBSAN_BOUNDS=y
 # CONFIG_UBSAN_ALIGNMENT
 CONFIG_UBSAN_SANITIZE_ALL=y
 
+# Sampling-based heap out-of-bounds and use-after-free detection.
+CONFIG_KFENCE=y
+
 # Linked list integrity checking.
 CONFIG_LIST_HARDENED=y
 
-- 
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212130116.997627-1-elver%40google.com.
