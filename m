Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBPNQT3ZQKGQE2XMHJUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id AB90517FEC3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 14:38:06 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 8sf2914236pgd.12
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Mar 2020 06:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583847485; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMR5yZTF6oGg35AGkyp4zIuA0x00ySfqoeWx3gzZLP8+l0lfxttzQj9Azlqps5HPDj
         Ptp5su+37d05Ed5WZyh3tOqAUIvVIjJMCEAy9A1bGPdHaGlE6/URNYaaFGl4Hm5dZHJ0
         eFQ0mzV0VS11Q7mOr4GPuCXAwlTokORFjIaBBFTfnQuWuYPQePSfIIZcKhE9HxBhiUOS
         rLSQ2O3PaBjnQD+PNazxkqoFa0iSwdzdSCTo9cdQhSNSKOc6+FF0t3C2SPAsiRHKE6Lx
         W4/zemDGheWTnn8vxhJK3DCn/nxGIKiKiVD30P34/3LxObNmcdKWd1wE23r5rDtcxshY
         lPwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=fgBpKxk2NaB9fXYUfocMGzFABCeQ0dVIlYXAESvcLsA=;
        b=0l6tbBp6Wh53TkFUzDPFANPRuHT0Uhgxr8vvDimhc98I5BGG13X95HkvYdUDLimEQi
         0VRsKKe5g2UKAmVsRXHH8FTme2w8iYVoUMRQi7/qfJe1C3LX7hLWZUgG0mLDmgN8Uc3j
         YKHARXUpxbDORy+HQANwyvXJxSYUxctsqkZ5BRUN5UE3mCSr5zx3d0HcP5/8xn2CW0+L
         cilsddL/dXVnlfpcyntTJqPYVwGdHFjdtdX4x0LdgSyZLkMj5joAytJOZnuGdBZjwAkE
         cb3zA3jLqQKXNEzqCT0w9le+3C1mU7zKswNij1yu0ouWJe820if6Zk8bIoCtj2CH/MZv
         i+rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=m7BI9M5R;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fgBpKxk2NaB9fXYUfocMGzFABCeQ0dVIlYXAESvcLsA=;
        b=VP2EK1czkqrmgwYcWTun33xvQWkkC8keMzoFPwZ79q/A6CUB6HrxmA54wKADmMziXi
         x+pjFHdOMh1uivbcL+rJXT0E+31tzbcZRKdt6F/UucVrBp1kUHDfPYwsUiMna6zvABEW
         WVnOSRD0oG6Idv24N5LyDEIqMl1U8UpYOTkbPJGE9Z5qgQFhBSJDyq9QnL/eMbAOeAS9
         XA71hcNwOQ9ZYa+iEUeMm+Mvokf0WHX2vtPRGfxa31Y+MUOkfYPyI2B7vHxP94WPLpL0
         JvRnztkKJxXZtAXiJcf1So1rYcgefGeShEdSyecBrqNZKt9LqmX4o41sc//pmE8Nzmx/
         44Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fgBpKxk2NaB9fXYUfocMGzFABCeQ0dVIlYXAESvcLsA=;
        b=WfJRFXge6Ki/sLBFl81qttAcmWPj7EyRbvHhMrVWQ1Jp7C1p0O4HVWBxpw0a2OqJfK
         FAjOMcamdqJeY1X8PVHLyUddlSLV4TBrgeqVtqTmlJe6IF/2opulqUNi171fnAFk41TO
         xyPuDHtjVIzZzq2g6HzzXq5tk0nbUokqrMdvskcOrYY1Epuo2Ds9nwWL0ZOMFOBPpMog
         C9+yvkRElZ5roPHQBRWn0hQwSzXCS45B1MScLR9KUTVUSU2lR3490vj6tAZMt49dj01v
         zwGjmklDvV+wshu5n9Yy7IiZjji9h4W3NaITpGBPzfpLTHATrRAsYSde6gBo7Z26INab
         Hi8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3cdzON41iLBXyXt1H7XOaevVHGGNu1eM9ilXpHrXURrDJXtOVk
	eTOg4nmBCcgGXsIvVFWT6U8=
X-Google-Smtp-Source: ADFU+vsm2ySG3cWwtPwtmRozdEZ4VyOlw8dfB+E9A7cRA++dbqTLn3LTuUst/ZZKROqrScknnKqBcg==
X-Received: by 2002:a63:f450:: with SMTP id p16mr21656973pgk.211.1583847485323;
        Tue, 10 Mar 2020 06:38:05 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a81:: with SMTP id w1ls6008367plp.2.gmail; Tue, 10
 Mar 2020 06:38:04 -0700 (PDT)
X-Received: by 2002:a17:902:9308:: with SMTP id bc8mr21568155plb.268.1583847484823;
        Tue, 10 Mar 2020 06:38:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583847484; cv=none;
        d=google.com; s=arc-20160816;
        b=jRJkixM3DM450CjaXkfEEKNblkJkfp2+nybtAWSVMiQEP20TUcRHxcHrpwIZoW578Y
         iJitcYWBGDb04NT5QF3CskxCJGkZy/nBr6Vwbr9JQnlgXGDDXu6cFPULmMWWyhANl1kq
         o13FFVX8uBsNws4lZe3xZ8QoXfc8Uthj+bTFS33QFIFuAbp2Gxo47OJ6PflO/DyhqIYh
         it+qUT7bPf2lKPdHJo4peX1U0oGgtLA7x8hFluKbTg/kERfX3iYEwHhKP6PS+OmDnTvm
         16Pu793M0JUBMeCWy2uP4yzS6V4klaQHg5QEzEvGQEojAOzzqk/NUJUQwr7dTflbF4vu
         fbQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=KLpE8ve97oAPJLQLYYx8zGcQlVMaeFiUkBk5Iqbenl8=;
        b=hO5UXk3KFw38qgB14AOd0P+lqxBkdHXVjVpAV5iyx3qV6GxlVPNkS2yMXrU8DK5ChU
         iTZnp/dsSJ7YdDgCX9lmo98+1gNcKsQGztk9lu5Z2eWEk7LczqZYUx/MlJxuXcagbZu8
         5IuH5ad7TgphAPnWlBmHci8IonIfC4tcLQJhyQVjeY/xHGD+FUBwaSggAMFPhARKuetm
         E3wfr0Ubrw8yhHSjagaSxgXsqgrKHrYtsLK885CmXztkoR4TrG03xYQPF+2E311UvJ2a
         zHKHpglKZdoAY79Ta/wnfVV9O9joThUWRV90wKJPKQSbC9SDlIU4QOfarhemsGYMYT4u
         R1NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=m7BI9M5R;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id mv5si136055pjb.0.2020.03.10.06.38.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Mar 2020 06:38:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id b5so12670092qkh.8
        for <kasan-dev@googlegroups.com>; Tue, 10 Mar 2020 06:38:04 -0700 (PDT)
X-Received: by 2002:a37:4986:: with SMTP id w128mr20381557qka.189.1583847483739;
        Tue, 10 Mar 2020 06:38:03 -0700 (PDT)
Received: from qcai.nay.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id v59sm3576687qte.19.2020.03.10.06.38.02
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Mar 2020 06:38:03 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
To: akpm@linux-foundation.org
Cc: aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH -next] lib/test_kasan: silence a -Warray-bounds warning
Date: Tue, 10 Mar 2020 09:37:49 -0400
Message-Id: <1583847469-4354-1-git-send-email-cai@lca.pw>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=m7BI9M5R;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

The commit "kasan: add test for invalid size in memmove" introduced a
compilation warning where it used a negative size on purpose. Silence it
by disabling "array-bounds" checking for this file only for testing
purpose.

In file included from ./include/linux/bitmap.h:9,
                 from ./include/linux/cpumask.h:12,
                 from ./arch/x86/include/asm/cpumask.h:5,
                 from ./arch/x86/include/asm/msr.h:11,
                 from ./arch/x86/include/asm/processor.h:22,
                 from ./arch/x86/include/asm/cpufeature.h:5,
                 from ./arch/x86/include/asm/thread_info.h:53,
                 from ./include/linux/thread_info.h:38,
                 from ./arch/x86/include/asm/preempt.h:7,
                 from ./include/linux/preempt.h:78,
                 from ./include/linux/rcupdate.h:27,
                 from ./include/linux/rculist.h:11,
                 from ./include/linux/pid.h:5,
                 from ./include/linux/sched.h:14,
                 from ./include/linux/uaccess.h:6,
                 from ./arch/x86/include/asm/fpu/xstate.h:5,
                 from ./arch/x86/include/asm/pgtable.h:26,
                 from ./include/linux/kasan.h:15,
                 from lib/test_kasan.c:12:
In function 'memmove',
    inlined from 'kmalloc_memmove_invalid_size' at
lib/test_kasan.c:301:2:
./include/linux/string.h:441:9: warning: '__builtin_memmove' pointer
overflow between offset 0 and size [-2, 9223372036854775807]
[-Warray-bounds]
  return __builtin_memmove(p, q, size);
         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Signed-off-by: Qian Cai <cai@lca.pw>
---
 lib/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Makefile b/lib/Makefile
index ab68a8674360..24d519a0741d 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -297,6 +297,8 @@ UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
 KCSAN_SANITIZE_ubsan.o := n
 CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
+# kmalloc_memmove_invalid_size() does this on purpose.
+CFLAGS_test_kasan.o += $(call cc-disable-warning, array-bounds)
 
 obj-$(CONFIG_SBITMAP) += sbitmap.o
 
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1583847469-4354-1-git-send-email-cai%40lca.pw.
