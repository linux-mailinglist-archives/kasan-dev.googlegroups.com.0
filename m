Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPOJXSDQMGQEXQMLS2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DA993C8A3B
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 19:54:06 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id b9-20020a2ebc090000b02901759363ccd9sf1623310ljf.4
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 10:54:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626285245; cv=pass;
        d=google.com; s=arc-20160816;
        b=E+rHgK+j3cHhBpqsjahTClnlnrMQbYnUzMKA9QYdU/L1enqVQC6DTnReD3WscTHgPY
         kKbKNS71/d6HlHmMK2UOY3suSYDfacI1rJPTbvSvxNFAzaUdmCOaaJRloVWt2dowPSgX
         bkPoLFES/ebeVFTLELq5kVeO+njtgyuEu07Dgle4NgXXmz9undC5PG+uTueswY1n/qyy
         e/0ZVk9Fa8G4we6ZSWaW55aVN16EQB4xwdABlLgFwrjBMpSQKtgDmYYoQdgbgs+bu+w1
         PE3dcrmeOvokmNfMoNO09ZgC3nSeEBqg6Rd1ZXggy19p1VY94RPAWRES9do7culeoSB0
         0kaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=65i3j7XyavcUmOl6bpz/x5kGG+E1orQHi5OvGzpKv90=;
        b=vI3HeahXQvdjnExQ4qavAiMc6YTuXJ30ddv0mK0NNpMxNWTRJKVfa0A3LoWW3JCQYl
         KH1Vv2Y8TyoPmGTh6MYkAxZ8VLC777kxyv7q2/RwHrdoOBBJdWqxd94yulamU3BF0s6Y
         C0jmrrUpe2QuyfNPcziGi/v5/g2mIZHFIrEiuCAe0m6E4D3epE8zYXAvWASAUrhXhtSp
         deP++NM0afLgoM1C1IIqL7GIkLMOwmOhD5h2QHeCLj4+afk5GllwNuC3K5mvBFRMGBEG
         HV1vTTgv3k4tBBV9HNL7Dkm61oVXvqPS6ag57I7AS4ShUVMbZCdH6ckffeoAwDUy5sQh
         /gFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+8mCmyu;
       spf=pass (google.com: domain of 3uytvyaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3uyTvYAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=65i3j7XyavcUmOl6bpz/x5kGG+E1orQHi5OvGzpKv90=;
        b=R7gL5Osgh4j0LAr5sTDuFkdkM+4F2+ZQcF9bGJCPreYGBsGX/5b4fRWesaCJbwgmI/
         ZF7VQyPqS1SNBbuPlJ+RgrzQTth+HkLP4XrN97mkrhELkoXaz2gxJnzWXYsg3EPQLqWU
         agwVoG4gvzhjo2DKsoV1dzFoKNny04DWeuXGQgopieWGpKPK205ip0NuhF7+Uv2xZ3KA
         cKevj2wb0ZPzTF00/G0vc3Z2ZFpFgUnwmQvGBzhgeOeyCJxgXcZimso4rt6Rv8RRJ5Tk
         qdgz060TbIAWZltjuJAUJO8sFkPQZwm14VDm0Klz/Vac1F2/m2e+zAJ9z3CCq4qVI0pi
         SKcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=65i3j7XyavcUmOl6bpz/x5kGG+E1orQHi5OvGzpKv90=;
        b=EFS4u7gWHHg1Ezh2ucE4DoTUuPZOxnGWsalGuRqN0hviU5IxDqNJUjLRZfI5Qxggtt
         3kwJ3w8kYdAY75Oi8bvh7uLVU9R+UqyWRyfZViPBXXe181VNccOY85SE0nV2fCqeiIoy
         tuwdUt1brhafj1sdyF6nel7Yh4puzYQzP5Vcz8ooaMvXoYk2yjt3POqr9aP/IeYNH5t+
         xcHHSSvbY4XX589AvaSBtf6w4BlXveKDEnZ/dL12I7W/+xqDwA+33xUjwfWcq/AmgUbq
         oY3ATqcHyvUPi7DsAEMvXObYNy1Z+3EjJOslV/IrHL0rRghO3c8I6pKLOX+bmuMVrKDz
         6IFg==
X-Gm-Message-State: AOAM533hx1MX25VUV9FaPCUuzfQQ136mVsKUtjmyg18n5bk3cYovIeRi
	Y8qAXnQbVCrHVKVrqYa7dxU=
X-Google-Smtp-Source: ABdhPJzUgsdvoiTQVPHsgpYnj+NaKoEpxqXRj1qzjzXLtAORMJQF965TUG4EvXefiWCPh3GBbs6Iyg==
X-Received: by 2002:a05:651c:b0c:: with SMTP id b12mr10389661ljr.190.1626285245488;
        Wed, 14 Jul 2021 10:54:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:508b:: with SMTP id f11ls2663075lfm.2.gmail; Wed, 14 Jul
 2021 10:54:04 -0700 (PDT)
X-Received: by 2002:a05:6512:20a:: with SMTP id a10mr6538333lfo.205.1626285244242;
        Wed, 14 Jul 2021 10:54:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626285244; cv=none;
        d=google.com; s=arc-20160816;
        b=fsE7A/8LwQPHEnYxOQQ+LushCQR71PFaV7SaSp9eElWkpRtyWYEHTIB8OfvAi2r+aj
         Fp4WwcfQodZ173ZKC2ZgdZlR/N5bUQ4ANtXgVH2sht+k3ePFQoacej0FNVaqfzxDPXi8
         4mvYlK4miHTqQkL41j8LGIrGOW4LhTHIWykKsi4JRNIy5pkBo724ijGxNP71gvl3FMIe
         N/Mx/W70hkfQu2jSc8EwKWENZvPKzu0ihTX0x4wGT16lp4TByTvNOylU2GCQ7qFlmje0
         KfuRAqfM3VFEbrR2pKxoNPnWslcFJrY6EHf9KU4OdpIcWNCaDkPkWi38nvkQIXJOG6ga
         hmcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=5+mFUXTtfVnX03Gm0Vc99a5tkKhSURuK+43WMml2RnA=;
        b=N+rFnxdNjKsOpUsZD3m4L8LLukmvjE4CQzjXHzUEh8bAHhaSZxlKnOs/pGi/BAjFWW
         /8MarhxOTM9apmJvpySaLI12sZUXunaSPtF5i9SwLtpkRD2Pdot+SbP7C1Rj1qAPaep/
         pyxPi87AGpWLML8L6wvfFoFNe59bj7YBkhRL7nOZKaLrvca5/kc+EBerUJXdToKFe92W
         pwYvFgSSwxwbMptmPc+1OlUy/by0V6pRo+1cuf67Ny1NOWChOMg2ZoXaWDyFTu/iaKao
         JW5ZbZUEhYMvmQwvFTWkPExeFNfwoFVkXasN3LZkFSCl39AmPkqo9oaiFFs6E+pbJMAj
         YS3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r+8mCmyu;
       spf=pass (google.com: domain of 3uytvyaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3uyTvYAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id d6si56175lfk.4.2021.07.14.10.54.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 10:54:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uytvyaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id c20-20020a2ea7940000b029013767626146so1593747ljf.15
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 10:54:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:41c4:bc71:d9ee:7fdc])
 (user=elver job=sendgmr) by 2002:a19:d609:: with SMTP id n9mr8907419lfg.198.1626285243714;
 Wed, 14 Jul 2021 10:54:03 -0700 (PDT)
Date: Wed, 14 Jul 2021 19:53:12 +0200
Message-Id: <20210714175312.2947941-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH mm v3] kfence: show cpu and timestamp in alloc/free info
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, corbet@lwn.net, 
	linux-doc@vger.kernel.org, Joern Engel <joern@purestorage.com>, 
	Yuanyuan Zhong <yzhong@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r+8mCmyu;       spf=pass
 (google.com: domain of 3uytvyaukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3uyTvYAUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Record cpu and timestamp on allocations and frees, and show them in
reports. Upon an error, this can help correlate earlier messages in the
kernel log via allocation and free timestamps.

Suggested-by: Joern Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
Acked-by: Joern Engel <joern@purestorage.com>
Cc: Yuanyuan Zhong <yzhong@purestorage.com>
---
v3:
* Fix copy-paste error that resulted in always printing alloc cpu+pid
  (Reported by Yuanyuan Zhong).

v2:
* Rebase to v5.14-rc1 and pick up Acks.
---
 Documentation/dev-tools/kfence.rst | 98 ++++++++++++++++--------------
 mm/kfence/core.c                   |  3 +
 mm/kfence/kfence.h                 |  2 +
 mm/kfence/report.c                 | 19 ++++--
 4 files changed, 71 insertions(+), 51 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index fdf04e741ea5..0fbe3308bf37 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -65,25 +65,27 @@ Error reports
 A typical out-of-bounds access looks like this::
 
     ==================================================================
-    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa3/0x22b
+    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa6/0x234
 
-    Out-of-bounds read at 0xffffffffb672efff (1B left of kfence-#17):
-     test_out_of_bounds_read+0xa3/0x22b
-     kunit_try_run_case+0x51/0x85
+    Out-of-bounds read at 0xffff8c3f2e291fff (1B left of kfence-#72):
+     test_out_of_bounds_read+0xa6/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
-     test_out_of_bounds_read+0x98/0x22b
-     kunit_try_run_case+0x51/0x85
+    kfence-#72: 0xffff8c3f2e292000-0xffff8c3f2e29201f, size=32, cache=kmalloc-32
+
+    allocated by task 484 on cpu 0 at 32.919330s:
+     test_alloc+0xfe/0x738
+     test_out_of_bounds_read+0x9b/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 The header of the report provides a short summary of the function involved in
@@ -96,30 +98,32 @@ Use-after-free accesses are reported as::
     ==================================================================
     BUG: KFENCE: use-after-free read in test_use_after_free_read+0xb3/0x143
 
-    Use-after-free read at 0xffffffffb673dfe0 (in kfence-#24):
+    Use-after-free read at 0xffff8c3f2e2a0000 (in kfence-#79):
      test_use_after_free_read+0xb3/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#79: 0xffff8c3f2e2a0000-0xffff8c3f2e2a001f, size=32, cache=kmalloc-32
+
+    allocated by task 488 on cpu 2 at 33.871326s:
+     test_alloc+0xfe/0x738
      test_use_after_free_read+0x76/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    freed by task 507:
+    freed by task 488 on cpu 2 at 33.871358s:
      test_use_after_free_read+0xa8/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 2 PID: 488 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 KFENCE also reports on invalid frees, such as double-frees::
@@ -127,30 +131,32 @@ KFENCE also reports on invalid frees, such as double-frees::
     ==================================================================
     BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
 
-    Invalid free of 0xffffffffb6741000:
+    Invalid free of 0xffff8c3f2e2a4000 (in kfence-#81):
      test_double_free+0xdc/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#81: 0xffff8c3f2e2a4000-0xffff8c3f2e2a401f, size=32, cache=kmalloc-32
+
+    allocated by task 490 on cpu 1 at 34.175321s:
+     test_alloc+0xfe/0x738
      test_double_free+0x76/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    freed by task 507:
+    freed by task 490 on cpu 1 at 34.175348s:
      test_double_free+0xa8/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 1 PID: 490 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 KFENCE also uses pattern-based redzones on the other side of an object's guard
@@ -160,23 +166,25 @@ These are reported on frees::
     ==================================================================
     BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
 
-    Corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ] (in kfence-#69):
+    Corrupted memory at 0xffff8c3f2e33aff9 [ 0xac . . . . . . ] (in kfence-#156):
      test_kmalloc_aligned_oob_write+0xef/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#156: 0xffff8c3f2e33afb0-0xffff8c3f2e33aff8, size=73, cache=kmalloc-96
+
+    allocated by task 502 on cpu 7 at 42.159302s:
+     test_alloc+0xfe/0x738
      test_kmalloc_aligned_oob_write+0x57/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 7 PID: 502 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 For such errors, the address where the corruption occurred as well as the
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index d7666ace9d2e..0fd7a122e1a1 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -20,6 +20,7 @@
 #include <linux/moduleparam.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/sched/clock.h>
 #include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
@@ -196,6 +197,8 @@ static noinline void metadata_update_state(struct kfence_metadata *meta,
 	 */
 	track->num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
 	track->pid = task_pid_nr(current);
+	track->cpu = raw_smp_processor_id();
+	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
 
 	/*
 	 * Pairs with READ_ONCE() in
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 24065321ff8a..c1f23c61e5f9 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -36,6 +36,8 @@ enum kfence_object_state {
 /* Alloc/free tracking information. */
 struct kfence_track {
 	pid_t pid;
+	int cpu;
+	u64 ts_nsec;
 	int num_stack_entries;
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 };
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 2a319c21c939..cbdd8d442d0b 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -9,6 +9,7 @@
 
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
+#include <linux/math.h>
 #include <linux/printk.h>
 #include <linux/sched/debug.h>
 #include <linux/seq_file.h>
@@ -100,6 +101,13 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
 			       bool show_alloc)
 {
 	const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
+	u64 ts_sec = track->ts_nsec;
+	unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
+
+	/* Timestamp matches printk timestamp format. */
+	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+		       show_alloc ? "allocated" : "freed", track->pid,
+		       track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
 
 	if (track->num_stack_entries) {
 		/* Skip allocation/free internals stack. */
@@ -126,15 +134,14 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
 		return;
 	}
 
-	seq_con_printf(seq,
-		       "kfence-#%td [0x%p-0x%p"
-		       ", size=%d, cache=%s] allocated by task %d:\n",
-		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
-		       (cache && cache->name) ? cache->name : "<destroyed>", meta->alloc_track.pid);
+	seq_con_printf(seq, "kfence-#%td: 0x%p-0x%p, size=%d, cache=%s\n\n",
+		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1),
+		       size, (cache && cache->name) ? cache->name : "<destroyed>");
+
 	kfence_print_stack(seq, meta, true);
 
 	if (meta->state == KFENCE_OBJECT_FREED) {
-		seq_con_printf(seq, "\nfreed by task %d:\n", meta->free_track.pid);
+		seq_con_printf(seq, "\n");
 		kfence_print_stack(seq, meta, false);
 	}
 }
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210714175312.2947941-1-elver%40google.com.
