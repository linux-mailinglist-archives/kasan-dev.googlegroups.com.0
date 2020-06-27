Return-Path: <kasan-dev+bncBCF5XGNWYQBRBTGS3X3QKGQEVA4BOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B64F720C2D6
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Jun 2020 17:44:13 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id k1sf8052741otb.23
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jun 2020 08:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593272652; cv=pass;
        d=google.com; s=arc-20160816;
        b=cXjQU1RUEJru56SJs920ZqBeqvhT/PKrn2+7Bp51ICqFbgoB7y26UxGxV4eb2ZR48e
         8qr3sn6+TMVk45DFaC6rB+LakiUd6yM8jN+vq2vl7xecF5ed9osd2C95ZIHpApWf1udN
         in4Jbt5kx1kOxrAtHipuzgRizWctcmD+RN3nnPlQih432YvNrbjy0O7icq+HBmesiA/g
         P2KCFtw2APvhYIBXiF8FAeLYarjqPDWB8geM0pzTRYHyqfH9SWagFT9LTEyGhYMjwTrn
         a5U6d0IBqnywPKPUUNqIo9HGr+hFnWKZMmVwddvNvSoLSZXimusOPB50v/iCT7BI85/j
         yv8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OTbiYxXg0AQ3XC/PEbThUn948/L0U8h+Vk7o2nxM9A4=;
        b=NKiGroh01i/UmeM7Aq/wESjfSSf4hhIAolTbQ+dSy6V59bCgKMOTbyndyplTDqQ6PQ
         /EBWKsVbNpdNPW/gI85PgEx5o1QAwpKzWnDDXXwrn2OIsAULzdeXLIrLrApxyF5I6gmG
         Fwt4YbTNFP6NuTagDpKBoFyetSw4q9zOsIK7p4e8OC/WBRvZi9v5XhkmejS+BnI87qpt
         TqY6p2EhvxbrNPUtXveKirhSVtEcpX7kZoJjc4vZslqi4r1XQNvlrStJgqGljBIr87xh
         YHRiJL6AekQgFAGqMQ9g1fe8bGQ8AYYY2LzbjecOomVd2K2/aFeaSPI22ENy+W8r3Y0F
         8yNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jiwENKYx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OTbiYxXg0AQ3XC/PEbThUn948/L0U8h+Vk7o2nxM9A4=;
        b=Wjv64aB71vtBSQ9YvrLdb761etnM/OFuvl1mvKOH9zn/H4ZU9rF2M5RqrCjyiCLk/j
         oD5TYWnTdHu4Fc/B+mKX0uEaxtJPApMwumTmKTQ3Gv+w0lNcQFdjbUk7pnkmxottaXox
         tXqwqYxg4OQPjBYzRisvXxtFt4Bls6AiXnnTAREAUA+LJSo9hblmKB0HtRIoHKs5XjAI
         nwZCOvnGrCcmLV5+EOSUzgqg0DRBlTIYTnk5VbIG92vYdnl9afAIqNTnVrBoJsSFS5UN
         atuPbEhPL3HZ4AH8MVZpfK3Fegtn4CVAAMu87HmFb3fBJtBjlSnYlelP+22970X4/GMp
         35xA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OTbiYxXg0AQ3XC/PEbThUn948/L0U8h+Vk7o2nxM9A4=;
        b=Qe6kCVH4wr5IMyIWRHaJ9h/R4XSIm/Ac8TGCn1vMQLBG5/ZhVWZEN0L651N3i4f6xJ
         p+RiK3G61S6EVgEsSDhVSFkCJtnX2+rJKUHMyWV1BPJFS3O4CEUgPkew0jsXZHrDFiVq
         utIUkP1gQb5u4KoGbVT1dp5Ogkpt/ZFrUBJ7nAbV1UXnpMQpnK7pvAtG0cGdwTcrjftV
         OQKlcGXvhXuHBg31UvXpZIFR02veY+f44FQQMzHScauzp4Q06a/oDH+GR12AAoChVyNW
         p2VchyLkwGi2w1zFZhe2Dyt/DJQcD2XP6X63c6Wq/KCd0pG5s3tBh6mGySN8gxUHkOO+
         ZaZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EgQPUtC4LIGcKmbm+sJ1tCgSTbzaioHdoxu+Ziy3y3ktPFiSe
	coVFtPyOXacp/ZkcXVZzmMU=
X-Google-Smtp-Source: ABdhPJxbc9DHUmrlYQBsm1toa6y5v27eiqnwlwYpmcSmUNZJpWrkievgoEatTd5mSY9G8EV9oP4/cA==
X-Received: by 2002:a54:4089:: with SMTP id i9mr793072oii.169.1593272652184;
        Sat, 27 Jun 2020 08:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cfc3:: with SMTP id f186ls219265oig.11.gmail; Sat, 27
 Jun 2020 08:44:11 -0700 (PDT)
X-Received: by 2002:aca:4307:: with SMTP id q7mr6328000oia.147.1593272651891;
        Sat, 27 Jun 2020 08:44:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593272651; cv=none;
        d=google.com; s=arc-20160816;
        b=VQqNZxPlYpbvISivz8TiDMGDlsyX5nF4iJcZmd3rs9SVYDCUTrPn79rSFDe4ttYYaE
         r/D79+skHFhcZin5cH/okD4DcVIGTbVcZuUPx7uUPPGyKHweXWnH+zhKOVL+f8Pwtoj0
         Ty1nCiTjBfAgGKDhptlSwmibezjecyn/IfloufP0kPsb1/amwG6dpa22oDcj8ke8HEo1
         dTo097RlGy94hWvogcMXh3mSy0NjF4vRjGv6QecsctMNqSrMe1Xh93QFwvMo6/Pg1rt5
         kc9kxCc2ZkYCQDmZXH4XyO93+Cic5SaU9ooXRCmOnCxh32MqyFyUO/2CT800/sdkcY9B
         zWhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9ahst1LcMGvptdzipciPn0ZwzebgDhHbEcFE0yzAK/o=;
        b=iP0FFGtZrxz+Ki7EhjqKvv15xzKZx99r3qc9Vxfy91/pOXGSFXNS+48ujKyRO4O2oI
         fLvnryC2G5K1fQkXzlsBSbaat0z0uv2QCqg3RuSc7egDdtpRcXAL2BLix3+2EZEIc3Gv
         +A82T0YI+WTa5mspDeZfUYmMyz55g4g7efufaKXKuJMBJI9QhTxd1qTyv4vKud9PTG4m
         4Vcrk07OqCHSvWixsYZ3i4ir6KtI0KlsX/dhgnGUyMQB+FHcDcd5JDiQGeQMZwcWP+ES
         cofbAI3cSAnRw11c3dbr2dwCJJIQv7P9GDAt3mcadr5m25TsbFkHQasNkKRMJEUbS6V8
         VeAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=jiwENKYx;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id l131si430094oif.4.2020.06.27.08.44.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 27 Jun 2020 08:44:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id u185so3957945pfu.1
        for <kasan-dev@googlegroups.com>; Sat, 27 Jun 2020 08:44:11 -0700 (PDT)
X-Received: by 2002:a62:1790:: with SMTP id 138mr7148783pfx.306.1593272651229;
        Sat, 27 Jun 2020 08:44:11 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id l134sm25302847pga.50.2020.06.27.08.44.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jun 2020 08:44:09 -0700 (PDT)
Date: Sat, 27 Jun 2020 08:44:08 -0700
From: Kees Cook <keescook@chromium.org>
To: kernel test robot <lkp@intel.com>
Cc: kbuild-all@lists.01.org, clang-built-linux@googlegroups.com,
	linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 4/9] x86/build: Warn on orphan section placement
Message-ID: <202006270840.E0BC752A72@keescook>
References: <20200624014940.1204448-5-keescook@chromium.org>
 <202006250240.J1VuMKoC%lkp@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202006250240.J1VuMKoC%lkp@intel.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=jiwENKYx;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Jun 25, 2020 at 02:36:27AM +0800, kernel test robot wrote:
> I love your patch! Perhaps something to improve:
> [...]
> config: x86_64-randconfig-a012-20200624 (attached as .config)

CONFIG_KCSAN=y

> compiler: clang version 11.0.0 (https://github.com/llvm/llvm-project 1d4c87335d5236ea1f35937e1014980ba961ae34)
> [...]
> All warnings (new ones prefixed by >>):
> 
>    ld.lld: warning: drivers/built-in.a(mfd/mt6397-irq.o):(.init_array.0) is being placed in '.init_array.0'

As far as I can tell, this is a Clang bug. But I don't know the
internals here, so I've opened:
https://bugs.llvm.org/show_bug.cgi?id=46478

and created a work-around patch for the kernel:


commit 915f2c343e59a14f00c68f4d7afcfdc621de0674
Author: Kees Cook <keescook@chromium.org>
Date:   Sat Jun 27 08:07:54 2020 -0700

    vmlinux.lds.h: Avoid KCSAN's unwanted sections
    
    KCSAN (-fsanitize=thread) produces unwanted[1] .eh_frame and .init_array.*
    sections. Add them to DISCARDS, except with CONFIG_CONSTRUCTORS, which
    wants to keep .init_array.* sections.
    
    [1] https://bugs.llvm.org/show_bug.cgi?id=46478
    
    Signed-off-by: Kees Cook <keescook@chromium.org>

diff --git a/arch/x86/Makefile b/arch/x86/Makefile
index f8a5b2333729..41c8c73de6c4 100644
--- a/arch/x86/Makefile
+++ b/arch/x86/Makefile
@@ -195,7 +195,9 @@ endif
 # Workaround for a gcc prelease that unfortunately was shipped in a suse release
 KBUILD_CFLAGS += -Wno-sign-compare
 #
-KBUILD_CFLAGS += -fno-asynchronous-unwind-tables
+KBUILD_AFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
+KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
+KBUILD_LDFLAGS += $(call ld-option,--no-ld-generated-unwind-info)
 
 # Avoid indirect branches in kernel to deal with Spectre
 ifdef CONFIG_RETPOLINE
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index b1dca0762fc5..a44ee16abc78 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -934,10 +934,28 @@
 	EXIT_DATA
 #endif
 
+/*
+ * Clang's -fsanitize=thread produces unwanted sections (.eh_frame
+ * and .init_array.*), but CONFIG_CONSTRUCTORS wants to keep any
+ * .init_array.* sections.
+ * https://bugs.llvm.org/show_bug.cgi?id=46478
+ */
+#if defined(CONFIG_KCSAN) && !defined(CONFIG_CONSTRUCTORS)
+#define KCSAN_DISCARDS	 						\
+	*(.init_array) *(.init_array.*)					\
+	*(.eh_frame)
+#elif defined(CONFIG_KCSAN) && defined(CONFIG_CONSTRUCTORS)
+#define KCSAN_DISCARDS	 						\
+	*(.eh_frame)
+#else
+#define KCSAN_DISCARDS
+#endif
+
 #define DISCARDS							\
 	/DISCARD/ : {							\
 	EXIT_DISCARDS							\
 	EXIT_CALL							\
+	KCSAN_DISCARDS							\
 	*(.discard)							\
 	*(.discard.*)							\
 	*(.modinfo)							\

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202006270840.E0BC752A72%40keescook.
