Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPUE5D3AKGQENMOIETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A95D71EF311
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jun 2020 10:28:47 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id l19sf4790514oov.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 01:28:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591345726; cv=pass;
        d=google.com; s=arc-20160816;
        b=XjbS8KsmXh8qnJHfVmMV70JOlssuMoJWyWo0vYI/SAE9IqOdwBEGI7q2YbmkOK9CpW
         KXgrydxeou+oNWBPBCoCwLOJP5DjDgIEebdNJ0+KaybMufI2vtAaw0bBzg8mnIlIJ9TQ
         S11n/mohVpMDeo8Uewv4SHYJvk0nIuqxEez3CWnRVaRYrc6Yh4bdOVCJ1HaThLFicv9F
         0egmlZ92p0d7n6RX5oonmmXnnJH5Vf64zevE5ngHMhp03LJAaPAoEpGWWDC3MyvE0ycm
         coVJmwTWDLM2sII2bMSGQxdoA6DRNNcX/9qqXWqRXx4uSdT4pkfmQXMWLfsNCOFRDukU
         /6YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=bMEmfOwfc1m83aBHVECGXL/Bc0TugOKHxOr2blTa6rU=;
        b=zBEqcYd6BrjWhcV8oIIi4ImytzhJCl5a2l4rG6wnt05s89INXS9xZ8kcKN2GBRhS7F
         ODF5nJK4QRmvo1Aehu+Tge9j1OiodeK4NRbtmbF0mX/C46m2YpLTHj7k0gVQg+cPOgzZ
         md6YBmpLynXDJbMW+2pOcjqBlNGZY7wIu1nncXg+YaWDiUm9eTBFWyYRx2JS8tUEnhJO
         BlgjyClYEaByI2TL6q6KhJr3Iv5ulKpZCsUofCjYs8VnpZd+llIit/+U6/aSMd0paEVS
         IHnrOvsCSfdRPPgODSdma4WMfqSjQ+nvdN8pI9dC5BAlH/TSSdKzPmvipVs4BzDHv8e2
         BXng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j5MQecjE;
       spf=pass (google.com: domain of 3pqlaxgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PQLaXgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bMEmfOwfc1m83aBHVECGXL/Bc0TugOKHxOr2blTa6rU=;
        b=Fip7a1viowXmjwwfQmQp7sXAPcsYc3dpetvEccwJxcQpJiS8Lo6Fg9EsfJHOsc8yDG
         wWq6WmlH25tNNHrn141HhKc9jHOvTGFUS/+DXSdq7zQRqMBJBzeBRvLoRoeA8WSK3zig
         FJq9SQ9q8JdysOaZuEVK65lTS+QiC7FeW36z7IA/KqsKYXM7c45r3q23b/Qpyt19xOSj
         S/hemO92obE8rp3lBNvs5ZJz/uOfbBQXhNoizgjR9GH3P2TrkqjA7idBJwKNDXK5wtsI
         6Nr68LPPa8EfGGLM59mnK+AW2tSk4kD+eH5Tq7Pq+vSM6qR4k/nWQZFBoq3Ak7IXBOz+
         zNWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bMEmfOwfc1m83aBHVECGXL/Bc0TugOKHxOr2blTa6rU=;
        b=m9gwgyUfdQs+SDc7vhWZ3/4dx5T2Jk7oaSM7psvKjenq9TxIGryDY8jHeBs2bsRNOl
         Alm0zk/lJOmycKeec2lrELwPy61b7N8L2Zb+hpwIy9KYrUlIaUKeIGGp7z2ak2MJMKNu
         Rot3aDbDXAmdHcD8dRAnJT/Ph1muimljydL01nWMc6APaVtaPkoIzO99fv7lO2K8wc32
         X3MzzEkSd0vuJdUUySY4x5hja/clwHA1DJKOsK6FWvbWP1A/oQpBtCTiEr0ZwST9kha6
         kiOCHQEZRTtW/XOilfdS2sTlxETVjoTH0p6Xyj9CFGI68VdoYzijkWhZiSDdYHLcL232
         TSKQ==
X-Gm-Message-State: AOAM5334WGk/upZA69XE1mfUx+NG9X0k94YSkpRqCTLpUNYcbqDZInIt
	h7JSLKrSmejqHUz1NUByQjI=
X-Google-Smtp-Source: ABdhPJxBGAL2fWudboOliN/TznHSzi67yTTI1TtNzYk8dDpQVTRDsxpWXdga1F+NZp5apu5AWc1tWQ==
X-Received: by 2002:a05:6808:149:: with SMTP id h9mr1265498oie.107.1591345726155;
        Fri, 05 Jun 2020 01:28:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2c46:: with SMTP id f64ls1886908otb.2.gmail; Fri, 05 Jun
 2020 01:28:45 -0700 (PDT)
X-Received: by 2002:a9d:34c:: with SMTP id 70mr6986397otv.224.1591345725813;
        Fri, 05 Jun 2020 01:28:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591345725; cv=none;
        d=google.com; s=arc-20160816;
        b=VovBu7qdbxra77ZbfEg4taufp0xFb6BFdCT0AKpa/MaIo06G5hsj+G8Y+BnP2fc/iZ
         dmEMDoWolXBNGyPUlcKKx6bNjpitKUe8aLF7uiyTsgulMVAyMYf0YlKwpAT82mE9nnMK
         rWZVZtjmUz5NPq7NQh1Kelhtfw5ivy2pq/Rc/FFDh3GD/KBeP0z1X/PcncDPMAPE2gly
         EJYa8Ekayo9Kov0bQkn8P6gJGUA7BHokLyQrZyBRX59vNW08Qs9JEb/Il2dDJ+UAitTd
         ZidvEnZnAsN5exsbBYz5ActDtngbfWRFQ09werOzaEwqDCThAzEAP7HYzcEUwto3mt9t
         lDug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3PKodQpvSJ7s5tO6EtbZDnjyyWXngJpHghjobV/Lh34=;
        b=undmbY5mcu2+jsAY2SB1X3uYFljQp4Jxrizz3ZA3v9YuPoEYmftsumtczC6mTc456f
         2fs7RuN+WEFp3zBxQFqAbIxIcnSu20gtVw3h5nIn7PkoT0NjV4m2x3AH23B2Xj3psTdc
         KKIfErufsrJTpjv6K94vZK+3FYf6BHSTugOiOg8fIlZ+J2fzYW0fFt8n5O+CzpOvwN2t
         ilWFNq0niW19NgfAIoY8R0j5jld5aeUMpQCM+3xFfn+GBvRpFz+yJlqhTVdoWhrkbklF
         8DyOl+ovFrOVHnC/YHbcWsc0hAWTL1RqSZkv/w2jAKhpbpmbN6crjZjiYHKGquBGEJpX
         sPgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j5MQecjE;
       spf=pass (google.com: domain of 3pqlaxgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PQLaXgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id y198si42832oie.1.2020.06.05.01.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 01:28:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pqlaxgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id s90so11085255ybi.6
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 01:28:45 -0700 (PDT)
X-Received: by 2002:a25:9345:: with SMTP id g5mr13780734ybo.485.1591345725292;
 Fri, 05 Jun 2020 01:28:45 -0700 (PDT)
Date: Fri,  5 Jun 2020 10:28:39 +0200
In-Reply-To: <20200605082839.226418-1-elver@google.com>
Message-Id: <20200605082839.226418-2-elver@google.com>
Mime-Version: 1.0
References: <20200605082839.226418-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH -tip v3 2/2] kcov: Unconditionally add -fno-stack-protector to
 compiler options
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	clang-built-linux@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, x86@kernel.org, akpm@linux-foundation.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j5MQecjE;       spf=pass
 (google.com: domain of 3pqlaxgukcaykrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3PQLaXgUKCaYKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Unconditionally add -fno-stack-protector to KCOV's compiler options, as
all supported compilers support the option. This saves a compiler
invocation to determine if the option is supported.

Because Clang does not support -fno-conserve-stack, and
-fno-stack-protector was wrapped in the same cc-option, we were missing
-fno-stack-protector with Clang. Unconditionally adding this option
fixes this for Clang.

Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Do not wrap -fno-stack-protector in cc-option, since all KCOV-supported
  compilers support the option as pointed out by Nick.
---
 kernel/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index ce8716a04d0e..71971eb39ee7 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
-CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # cond_syscall is currently not LTO compatible
 CFLAGS_sys_ni.o = $(DISABLE_LTO)
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200605082839.226418-2-elver%40google.com.
