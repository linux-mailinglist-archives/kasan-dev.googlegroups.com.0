Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNU46XBAMGQEKP7JHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DEC0AE9F2C
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:18 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3a3696a0d3asf442124f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945335; cv=pass;
        d=google.com; s=arc-20240605;
        b=j6Mgu0YfVeKl3ukVOFrPUBYxncj6IO4sun5Cix/pUBFtzD18MO03J8Xlg4M3vJR1U3
         DMnGCUMBIBEiWuTWyPOT2F/6YVx7gyQFYD+CJroJ1UpYNOBgHnDKwHib3n0yEaL3NwFW
         T8jSVuuYtXnW/facpDSelr99X1EzwtVSM3LgL3Q+yRWPDUzuWqcrxj1rINrfWTi/ZFQE
         +C38M0LoUmY/mzhqwf6rJ7JF6bO/oY+X8mHUGv3Vv/g1qgsKTtj3RoVe6Ss3exbHF04t
         W33gUcedUr/caOljxJjKkxBU0W9O6yFrhzNz0npCVVmlADahdHik8XrNYEPidchdIHuN
         7AjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=JMI5ustE64IBPXnu4xoBZXVkWGHarM+Vt8PQWYZhm/o=;
        fh=EB2DqMDmVq/COp1YLk3o8+WBo2n89p1624zxp3GgzM0=;
        b=IsImfmO6x8zZ545rzhZBDcsZ3cf+ZIziJByx2eSYTBceTj4tlSKMB09f+UC065tWCu
         XdvfEzoMTp2kxeUjAhEsCgn7womKzgDvkeNRBdl+YCcTWXPvGPl6bkodzXEBskP8aSbr
         eEQ06Yb0uKsdANwv93+4AT0RADT9rLoiWHeg+iV5Y0O/oOn0PDoAemIEceA29hqtmMhc
         4Z/uo8Gxtf1qE5v+oE+aUMJk3ifxu+HTUVSGICOIxYZSpWHXY6v0Ki7ajrR0OpL56K+7
         M3q8u4wp9oNUlz6GVM/R76FyMr8qmAzQhJCsTmrXGUUzGcEYs7nyXMvWWNkKmKcSfU0A
         m6jA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EFABljvH;
       spf=pass (google.com: domain of 3m05daaykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3M05daAYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945335; x=1751550135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JMI5ustE64IBPXnu4xoBZXVkWGHarM+Vt8PQWYZhm/o=;
        b=xqED4TRFxG5u9gOnzkbtOs8ZXBDuH1eXRTyHOjcmPDp3dNZUm/34/FUV2aiGk7VjWT
         1Xq4huA3ikKTm0Ed4MONnd2EF1GlUcrBrg/9Ry1LGG2XaKarSte11AibeDPkkrxv4mOJ
         3LcM+H2wpchSf2ACwkl77bBOoVyANbWm4ltSf+R7MnYYIZe+G7Xzc1z+QuOx5Zne9YWB
         zhf6wajnzntTpsLnxuH50/22iJY61nRbaaNezmytPspwgPD4ONO/4hl2CQfVUBcug9C6
         T+hhdVAUklmIcqcasJ2mIawRV25st8s0Yue3ymqqCJ0QAFBMTY9h3nXxFXpFW4Vac7yJ
         C/RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945335; x=1751550135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JMI5ustE64IBPXnu4xoBZXVkWGHarM+Vt8PQWYZhm/o=;
        b=Eoz+M0dEF8SAe2z1mDDymGV7xXqJE6cHlnhwcg8g6ncnS9NNuFAcWxBBV0xSqzleej
         fRdJnl+UjcU5dUrLpVSpaeWgaLUh5NgpyDE+pTISZu2mUmSl6cs/0hA07Xh2Offv/oGS
         XanFPqBUoVnRmMA+BGWZGiXd/ezCmpC6GlZo7PniDrgiY+8smC9S19ZRgLXPSj67nyOh
         ODqzSy+Pbg4+dESt18R8KUbNPUO0oHhEN75GRy24WtPRHgH52TnJWf8pEuvMTUIVfUbu
         H0Cugx7Th/S5xpVJ+LJaanozI2q+zl+t5Jzzfzn+YqS+EXxm8tzUZQ4wxQUnl9Jaa2ye
         f74A==
X-Forwarded-Encrypted: i=2; AJvYcCX/fSaZONOPH0w8WjWDeDL7KneUwe1SZY9mDy6k09xY6alT9DojPp61P/vDYjGxM+xSesKHUA==@lfdr.de
X-Gm-Message-State: AOJu0YxatJu6X/qjFAi7ezw4lbl+tRNiaDaSj90KNJqdEbVzRIn4Gzgg
	5+nPlQIgp6pXp8t4m+4KdOH5E3lRp8a6TjZF7LqddCa5WIwzPnNxSCrn
X-Google-Smtp-Source: AGHT+IG6SeWDlpTmKBuOkZvNyqM9AJQ6L5b3spvZr3SJ2KU8VwJfkj5SFd0U/U39clS/MwkUbWRmhQ==
X-Received: by 2002:a05:6000:471b:b0:3a5:39ee:2619 with SMTP id ffacd0b85a97d-3a6ed65b3d6mr5448868f8f.47.1750945335011;
        Thu, 26 Jun 2025 06:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrqn9dMTzls//E6zu9i1jXB/blyMDtrZUqq9fzycWiWA==
Received: by 2002:a05:6000:2209:b0:3a5:7944:cb2 with SMTP id
 ffacd0b85a97d-3a6f321d0b1ls475654f8f.0.-pod-prod-06-eu; Thu, 26 Jun 2025
 06:42:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV65AWrT0VhGeoRGQUPheZBpBWePokOi1KGjzg7uY0seIwpMaTZeCAaLlfAg2xuh6yRSj7XoAfKUwE=@googlegroups.com
X-Received: by 2002:a05:6000:310f:b0:3a5:2cb5:642f with SMTP id ffacd0b85a97d-3a6ed64b8cbmr5350583f8f.34.1750945332461;
        Thu, 26 Jun 2025 06:42:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945332; cv=none;
        d=google.com; s=arc-20240605;
        b=Wl1d87f/Inq9oBGoekzfi6pExvE1nfd2lkrwO9rCb1sIMBu0Oo3DBZgmWc5WaVgYiu
         jaKcPEhyzyaQ8VNuh14C9sw8ZqA5vzJT5BYJUfkVzVO+Y7O7xhQtNUjC2BD/RxJ+sXJR
         XUDeUZkXYVGRZsAoyYhal1AeAIPL1hc5CWXMuHcKNaPugZj3+mg05hJHGBmB6o6nm3s8
         OLpKzjutOMiEnOXkk428dIQWs/E8k1LF1nUBjS9yO7mY7cvNzrQwA4t8Mk2M0V8fOsXs
         DxjVO1P6swrjimUfo8LuMeHt4eIvUGgIVrR59Q1qPNAeK0jVhvVTBcCCVqPGFge9NJbd
         aVZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=H2gpzKqZL1lxRtkvI/RoX8Rqd5NtVf1Q/oJAS1UNweg=;
        fh=QeQzuei37r9ZJlMAXZIQUx/LezD5nLNhfTwjM4FMvjw=;
        b=c0dM/Z/7+nnl/j9ZNuQdUMV2jL5Qt31UJWozJpO5Q6Vcmgf3xRsvcK4OHR5GX1EpnT
         Xu2ydPcYdb4jb21MPF12sCU07Ip65IdXIKRQNEeB8B1udGcIr5U9Fm45Yvabm+FGchVI
         gHmFMG4d1gxBSH19GSzBML3Lb5hdQu0a+KAt0FRIHY+QebvvcnMzHOYAG3vS+uJ6GbvZ
         Ukl4yL/aXRrOAb1t1yIfbrmlV/hQxj+eynm6v55d+Kvs6rRNErFom6bCWlzSocoCiVBA
         zjNIlPMxesPRyS2zFp3L/3JUpLt2559HsqhAVVcEoMvxFW9NE7w2Ihu+OmOvqQCsBw9q
         3VAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EFABljvH;
       spf=pass (google.com: domain of 3m05daaykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3M05daAYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fcff4dsi981835e9.0.2025.06.26.06.42.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m05daaykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-452ff9e054eso3982045e9.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU8VCBPxvenlLybZNc3jb8Kc6PNlg0STtwdWwlKdW4hsfuTHtAJM371XrzJmwf8EgCYpA0W94ScWss=@googlegroups.com
X-Received: from wrae8.prod.google.com ([2002:adf:a448:0:b0:3a5:7c42:1583])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:3103:b0:3a4:f7ae:77e8
 with SMTP id ffacd0b85a97d-3a6f2e8e297mr3438599f8f.15.1750945331958; Thu, 26
 Jun 2025 06:42:11 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:50 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-4-glider@google.com>
Subject: [PATCH v2 03/11] kcov: elaborate on using the shared buffer
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EFABljvH;       spf=pass
 (google.com: domain of 3m05daaykcy4y30vw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3M05daAYKCY4y30vw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add a paragraph about the shared buffer usage to kcov.rst.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Ia47ef7c3fcc74789fe57a6e1d93e29a42dbc0a97
---
 Documentation/dev-tools/kcov.rst | 55 ++++++++++++++++++++++++++++++++
 1 file changed, 55 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6611434e2dd24..abf3ad2e784e8 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -137,6 +137,61 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
 processes only need to enable coverage (it gets disabled automatically when
 a thread exits).
 
+Shared buffer for coverage collection
+-------------------------------------
+KCOV employs a shared memory buffer as a central mechanism for efficient and
+direct transfer of code coverage information between the kernel and userspace
+applications.
+
+Calling ``ioctl(fd, KCOV_INIT_TRACE, size)`` initializes coverage collection for
+the current thread associated with the file descriptor ``fd``. The buffer
+allocated will hold ``size`` unsigned long values, as interpreted by the kernel.
+Notably, even in a 32-bit userspace program on a 64-bit kernel, each entry will
+occupy 64 bits.
+
+Following initialization, the actual shared memory buffer is created using::
+
+    mmap(NULL, size * sizeof(unsigned long), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
+
+The size of this memory mapping, calculated as ``size * sizeof(unsigned long)``,
+must be a multiple of ``PAGE_SIZE``.
+
+This buffer is then shared between the kernel and the userspace. The first
+element of the buffer contains the number of PCs stored in it.
+Both the userspace and the kernel may write to the shared buffer, so to avoid
+race conditions each userspace thread should only update its own buffer.
+
+Normally the shared buffer is used as follows::
+
+              Userspace                                         Kernel
+    -----------------------------------------+-------------------------------------------
+    ioctl(fd, KCOV_INIT_TRACE, size)         |
+                                             |    Initialize coverage for current thread
+    mmap(..., MAP_SHARED, fd, 0)             |
+                                             |    Allocate the buffer, initialize it
+                                             |    with zeroes
+    ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC)    |
+                                             |    Enable PC collection for current thread
+                                             |    starting at buffer[1] (KCOV_ENABLE will
+                                             |    already write some coverage)
+    Atomically write 0 to buffer[0] to       |
+    reset the coverage                       |
+                                             |
+    Execute some syscall(s)                  |
+                                             |    Write new coverage starting at
+                                             |    buffer[1]
+    Atomically read buffer[0] to get the     |
+    total coverage size at this point in     |
+    time                                     |
+                                             |
+    ioctl(fd, KCOV_DISABLE, 0)               |
+                                             |    Write some more coverage for ioctl(),
+                                             |    then disable PC collection for current
+                                             |    thread
+    Safely read and process the coverage     |
+    up to the buffer[0] value saved above    |
+
+
 Comparison operands collection
 ------------------------------
 
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-4-glider%40google.com.
