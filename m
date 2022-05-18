Return-Path: <kasan-dev+bncBC6OLHHDVUOBBI6CSKKAMGQEOOEZ2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D35252B371
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:32:53 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id m9-20020a4abc89000000b0035e964b0813sf735315oop.16
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652859171; cv=pass;
        d=google.com; s=arc-20160816;
        b=ivqaB3MRgSD/1GKxzROO6oHbWOG+Euu9WYBNj+UO7RpUMCyjJRptdhaXKNl5k92ske
         yC6NKtk81nKWyPPE5G+f2zkZvIMXk7B3S6QlX5j3MQDlWpLEvuluZ3Ak8yklqNVyXAZh
         4VdBkKDLXFHiTYDnTGjojYLF0Lbz8nKQZLvKaPFg6SSQfqka72AhQ5Wh5xs18iP8I1z5
         1Xh9SXiOJ8iOr26hGtsC2pAPaVzzb1fJDG2Zon+C1sW2hElStagBrery8JEogaJXaQwV
         RES90JqQNOs6ULzU+782OC20dQhemidwtfHmK1jUEArJHihSVRu5rWXKPx8noTXc1FcF
         nwRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=sG/cAKhfQ+z+Vk0OKQDQ1q5eTEOHTQoS6wMSJqx0Xq0=;
        b=0wvu14y8COdHMMmRb86BOqvkl3SeNWBeFZ/GlyDubfSj076fj9bEooUGFlK3yAyXi/
         hLerp9/OLa5XJ3ETlHZcsX+IuCq+aGQ2NkgkzcNZAQ80Dc7qAxxbpiE1cGdrsHJOV0sJ
         dFlzs0869cNyF6p8X78s7ZyxRp/fncwTHw3h8LOimd+tuZO+t9DqQQFQXgi0O4y+pOQM
         9gVJ+nKxkO0P22rywmc35UjZcgPNGpJ0fhRSpor2dJkvz2bH0vjFQcfXpF3VBW+6aoXQ
         sA7ubEAYC2dM5ALaCLVb40Lt71+ri6WGMQHI6inu88dB4CmNBTxH0AuDW08bXOCBCa0o
         CtRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ETFp28WB;
       spf=pass (google.com: domain of 3iqgeyggkczeyvg3y19h19916z.x975vdv8-yzg19916z1c9fad.x97@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3IqGEYggKCZEyvG3y19H19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sG/cAKhfQ+z+Vk0OKQDQ1q5eTEOHTQoS6wMSJqx0Xq0=;
        b=letlq3x2ipueASwW7PAqyW7aeL0ga7vuAkNxFaxMmncP2kpUxXYOqG4RjcO6zLa32i
         xJKzZEee88fPMRudMPRC5jrkFaQlgLwBgg4lUomR/qGT9nYnw6K81BjksLEECFGfvg1L
         I9PrIB3XmM/WUT/CkStPKqnFMClAJmleDx4zwKfBID9IjEWHTQBLv7Scf9Vl9lloQRpo
         WQBy8yPYUnZkVh5UmCwxgRvXcdnul+TkJUMtisJEyKW9VFmzcRjzs/EdUH5OLWtEUnk5
         1HYopL+k98S1u7b7pZfMudrIWDuPwqSr8TtnbsVOSue5itm05r6pf3LYILKD4T+LHzxc
         l6aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sG/cAKhfQ+z+Vk0OKQDQ1q5eTEOHTQoS6wMSJqx0Xq0=;
        b=QeagUoqqz4ni60IV05/EGYEYFSqDBPgvqkyk8X8g+72FbO/WPn35FulbRjpo2yI7nR
         1OyfYYj88stnnd4YTpl6vw5trvjGd2x2fMunRNVN6d5Nj5MFwj+MAGsFeMRO9hBc9DL9
         VdFLfqaDkN7zgx4z69C+IAlQ0ZSn41lRl4G6hIi4KAMsBtzDEKICJU8zGg3FScR/nTfY
         McCw0QvknNr2GNKJIrV5KRJHmJSLp/S+IXHAwTjnFOGmrHhNGGVBBjPbJubZgfLZwrJP
         KatA4AmQ0ZK4RVdI0miQXDL0icWJla053rF6Atk1II9qVqSRadyNp7euutRO2h/TmYX7
         /AjQ==
X-Gm-Message-State: AOAM533JH+G+fkFhkXe+Qdkxs1aCpKBx0B+qTGAB2qlWkji0/WkgFwOu
	Uvujf2TETA5qakF9Remcpy4=
X-Google-Smtp-Source: ABdhPJxK2EgmQXVrd/o7ANoQsrV3oRg7hT1F4vdR1s7vMa2Vfc7975R7sauTAZtcaGlauUP4w6g2tQ==
X-Received: by 2002:a05:6871:6a4:b0:f1:890d:a7c8 with SMTP id l36-20020a05687106a400b000f1890da7c8mr10165377oao.42.1652859171736;
        Wed, 18 May 2022 00:32:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4486:0:b0:326:4611:e0d with SMTP id r128-20020aca4486000000b0032646110e0dls7978784oia.7.gmail;
 Wed, 18 May 2022 00:32:51 -0700 (PDT)
X-Received: by 2002:a05:6808:220e:b0:328:a2a1:333 with SMTP id bd14-20020a056808220e00b00328a2a10333mr18140107oib.22.1652859171342;
        Wed, 18 May 2022 00:32:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652859171; cv=none;
        d=google.com; s=arc-20160816;
        b=vUYfRs1g2NnmtdGZr9xQqA5dX36OrI+WAmFM9m78UpsKQ/F82fwIOpfWGVh8ik4v9m
         zySiGNjfo3TJC6+GYr+ELv89vVp4ZELxwu9fikCig2fkQRhPx6F/xMDADsZSew9owD7W
         tkewzP/ZCUkHzvvIS+r072KAX6I5oorpcmalt/uE2UjGFpGlifp+TLh11e/i0E9M7uHv
         T1ZV5+Z3hcDWThia4Bg7QNmt1hdH+wdMq+/G2y07LxM2io7pSIU0R12ISVBIbR8Nb9cc
         zvS1T2OFc631BiGaqkS2R+O2OZfsmTXS0qpXikOO6ksB0RrLRVT1uVEPnHX6gujJHjpj
         TACQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=iQ99kfljfaTYAW2ip5rvwd86TKnP6A3rksjwxYstBo4=;
        b=DUSR0osV+WEDcUJLVF0mOWH+pH4WLyasOaxg+kar/L1v8416kK7K0xXP0Xq9wTIDGI
         MCnDLr3JJXehHbUEvUkdQ3rgEkPlfwYKljI0IiTs5C71NnhLeMXFn3JT5EiX+KbKkNES
         rwHi3fnHbrxsoV2z5w9YEWJPvVEPRUx5BuLNGJWh8fDAaP9gv+o+ZvLWcB4vhxg4IlnC
         fx2jH4R7hfowCPNV6et+gwMpW1Nyrsfu66CFGeJOKw8aII+HuJ+AEU+Z2aw8ptmbRfn6
         slu5/E9s0nQIJLgtO45R/VRptj52QcIbAslkyU3ek++xIE3DJv8BOUY717FhKQ2SFI6C
         utYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ETFp28WB;
       spf=pass (google.com: domain of 3iqgeyggkczeyvg3y19h19916z.x975vdv8-yzg19916z1c9fad.x97@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3IqGEYggKCZEyvG3y19H19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id fo13-20020a0568709a0d00b000ddbc266799si210632oab.2.2022.05.18.00.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 00:32:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3iqgeyggkczeyvg3y19h19916z.x975vdv8-yzg19916z1c9fad.x97@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id rj11-20020a17090b3e8b00b001df51eb1831so2762563pjb.3
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 00:32:51 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a05:6a00:b4f:b0:518:161a:ed40 with SMTP
 id p15-20020a056a000b4f00b00518161aed40mr3418498pfo.19.1652859170621; Wed, 18
 May 2022 00:32:50 -0700 (PDT)
Date: Wed, 18 May 2022 15:32:31 +0800
Message-Id: <20220518073232.526443-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.550.gb090851708-goog
Subject: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Marco Elver <elver@google.com>, Shuah Khan <skhan@linuxfoundation.org>
Cc: David Gow <davidgow@google.com>, Dmitry Vyukov <dvyukov@google.com>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ETFp28WB;       spf=pass
 (google.com: domain of 3iqgeyggkczeyvg3y19h19916z.x975vdv8-yzg19916z1c9fad.x97@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3IqGEYggKCZEyvG3y19H19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
8-cpu SMP setup. No other kunit_tool configurations provide an SMP
setup, so this is the best bet for testing things like KCSAN, which
require a multicore/multi-cpu system.

The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
KCSAN to run with a nontrivial number of worker threads, while still
working relatively quickly on older machines.

Signed-off-by: David Gow <davidgow@google.com>
---

This is based off the discussion in:
https://groups.google.com/g/kasan-dev/c/A7XzC2pXRC8

---
 tools/testing/kunit/qemu_configs/x86_64-smp.py | 13 +++++++++++++
 1 file changed, 13 insertions(+)
 create mode 100644 tools/testing/kunit/qemu_configs/x86_64-smp.py

diff --git a/tools/testing/kunit/qemu_configs/x86_64-smp.py b/tools/testing/kunit/qemu_configs/x86_64-smp.py
new file mode 100644
index 000000000000..a95623f5f8b7
--- /dev/null
+++ b/tools/testing/kunit/qemu_configs/x86_64-smp.py
@@ -0,0 +1,13 @@
+# SPDX-License-Identifier: GPL-2.0
+from ..qemu_config import QemuArchParams
+
+QEMU_ARCH = QemuArchParams(linux_arch='x86_64',
+			   kconfig='''
+CONFIG_SERIAL_8250=y
+CONFIG_SERIAL_8250_CONSOLE=y
+CONFIG_SMP=y
+			   ''',
+			   qemu_arch='x86_64',
+			   kernel_path='arch/x86/boot/bzImage',
+			   kernel_command_line='console=ttyS0',
+			   extra_qemu_params=['-smp', '8'])
-- 
2.36.0.550.gb090851708-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518073232.526443-1-davidgow%40google.com.
