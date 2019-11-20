Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJFD2LXAKGQEOVAZ6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 646C31030F0
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:06:45 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id c77sf14806368qkb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:06:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574212004; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0ItcuXIPnmeqn9OahsB0/eUCCEUmigyflAy/8i7g5WW1jlc0u1rYpuGMOCfs4/eo9
         2QJhhElEwbKWaBKDylfJA9R4Nf7ucL+9QUIgdY97LtkHCujnPiXfkL8O6WOgIJ73d0EW
         VYLcFit6VuH6r8sZsqqsPsvZOc/jxNpCvqg44CpjYj4tglALPSj6kPCexv3E7vyFLQOJ
         GTGx35y6CrNkad0SFvwIUxjtmKwWMdEoqdnujalN3wMrvkNTcOvXRAd6AcQj0gbkURO9
         1LdHR6UXeCUD+WGe4vLvVoIKNVaZplTSp5wub5tolREjEy/YMRolP9Bb3IZ0q9Wy5tu2
         v7oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=FNJz+UAEXO4jEM9UetVjR5pkjs6WJP0+29yh8c7ohmw=;
        b=oOpjN7ZcBomoq3l75+N+sGO6hOIv+P30CjUwx4l3pmCEgxmtxz2NBV4QBDst//kbB0
         7DThIm7PvJrsExtKR/C0ULWjWc3tt9RgtFbykxq9UnSycdbCNU8thBmqXAU6BkNmXfPK
         p8qvX8rRAQpHGNeSpGYaIucmixneQ7+tfmaCZF6FX4eWYfwF7661ZINbDnVHHFZXmV0Z
         07kskzYxGD/Ujm9tdZTpbPtZiSPjRqRh4mWwaBPyTV+q5OmslZ/GboawQzj/064CqVP7
         12+2/U6WtILRRkGzX8z1IaK8Fa44IUCeU9tkhKgVOGt9tUiqq27M03kFSvocr+TRjsUW
         v7DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Dl72hrPu;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FNJz+UAEXO4jEM9UetVjR5pkjs6WJP0+29yh8c7ohmw=;
        b=fNNOqqs6jfwLdkFPG/yUc3cPzhvllhevweXb/Qiq2GzBe4xcdiLQTRmkgmq8cKCTVO
         Vprpjon1I1frZ3w5xjkA4zOhXroJzyU3qUa8ZdfKzTnyKD5ONU9Drp6MXYbQsKAUhPDB
         lfrKzyTokfITomH7QO3r5QSoENk45sXqudxqzGR6gjMWbodaDTIjM/K/6cY8b7JoRIqk
         0JUSPOT64jcPr7N/eqGobTWpnlVVWYphqZMueFDBIVE5EGADmRFbRpsNJuWEY47GhhQF
         wtpZo6/QD5yVk6Kpra95XRVF0iHxOahRv4s4kX1SZboqBpz9f/gRIQbESRzZZcaCPjqc
         g56g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FNJz+UAEXO4jEM9UetVjR5pkjs6WJP0+29yh8c7ohmw=;
        b=O8x989hetRqHXn+3fjRwYpMHkXIH0oJI9fLfK6lx2s3q1nX5lvzC49zUhV+pkk/kR5
         L8LqP6P4UWpOvw+PZKK4q6ziXJBDKiwB9oawJKbQ+LI5Z4XJZtRPW56/GDtExqmZU178
         iqOGoF/AUebbKumfp7CMNWQFgsK50mJIvZSo/bU5JmWi5XpjG8nTDMLN/XFHGwjUZcTA
         Hh3ZIuNty1iqsbdu71ZqwRk0ftye1QzJ4AUGwwG2TktBBA+9pdHSmu39OZ3zkydmhpHQ
         lZ3XfnJTUxF1iXtx3Z9pljIPsZsFCwCz7IYylcRJqdNTl0s4u/tREnZ+vFNueQBFdf7L
         e2lA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV2HfAvGMdu75x/tiVrpNggvcTB3laIis5Cg0ekqk399cpJVpK7
	C1V/mi3qTVvYYHV97XM2/vo=
X-Google-Smtp-Source: APXvYqw+VkBTK2WE+9B2MCv03vdQfC5Dnk903X1ZFlhzqKj46s7GoKUeKx2usk2b61fFGkZRR1W0gg==
X-Received: by 2002:ac8:60cc:: with SMTP id i12mr218247qtm.103.1574212004362;
        Tue, 19 Nov 2019 17:06:44 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4cf:: with SMTP id 15ls156289qks.10.gmail; Tue, 19
 Nov 2019 17:06:44 -0800 (PST)
X-Received: by 2002:a37:bf83:: with SMTP id p125mr135628qkf.165.1574212003971;
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574212003; cv=none;
        d=google.com; s=arc-20160816;
        b=vvW3HL+GgVh8/4WoXOj/vfkt/D5ojnJgIqZhMI9HfPJY6YSbQ/TBmhCABEIGk9muDl
         NIJk3JqTiosc391+Q62rqSRD3LqCpAzD3qXY/n9q/FUTS4Z9/W1/vEt2Q8BxsIFWfOgY
         uCNDpMto2atMvjQ3+aW5Dp1fh+MXRsGIIKz1fVw3nuabIc4gEnywMUI1cCXkZoNL5IAS
         udxCVltYWf39+SjqMLmccLw8nCiDHDFNQCRyaeDfVIHgkLKBTg/rJi6sXAA/3DcpAp7R
         aQa8bI2Glf1B2trYByGZvx0M6mXhBu+7sWsyjygoQ3kN9o0gHBihJwKzTSjd66ngSvce
         QpFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Qk+ofBX2bx2BOGB4TqoJ+/VT2N5xkCBYGbqC21Di0lw=;
        b=QAkhJgphjTe4B2nGw6SATSeYEbrYkOc3fDQsP74aCtwu8JKvXwjwQYS42A157i2MZA
         hinnxySSQbycOKEvafjBnUwU1p+ox03sDDSLOpopAKsaXoqWfqqcrZgph5BX5+iks7OW
         lovkkCyPFsCPTDLmZSh0igvYBZZqdsvtwPiiTrWAmtstFCv9QJ6T5QlkOEoAy6GvAJsl
         2yzS5vocMCogYnEreUsAdd5pe8OXRVYaaHGLWrRFoF2mXfWGdE66TOxYoAJMKRgoddOH
         B1VKnUuhrcflE7aa2tP3nTKkU6I02n0Gq6RSJ7nWDpV/+pKnljK7elBzvc2M9q/UPEQ4
         jccQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Dl72hrPu;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id o24si1450370qtb.2.2019.11.19.17.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id n13so13331444pff.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 17:06:43 -0800 (PST)
X-Received: by 2002:a63:5d10:: with SMTP id r16mr80693pgb.41.1574212003024;
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id j7sm4812325pjz.12.2019.11.19.17.06.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 17:06:41 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH 2/3] ubsan: Split "bounds" checker from other options
Date: Tue, 19 Nov 2019 17:06:35 -0800
Message-Id: <20191120010636.27368-3-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191120010636.27368-1-keescook@chromium.org>
References: <20191120010636.27368-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Dl72hrPu;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::441
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In order to do kernel builds with the bounds checker individually
available, introduce CONFIG_UBSAN_BOUNDS, with the remaining options
under CONFIG_UBSAN_MISC.

For example, using this, we can start to expand the coverage syzkaller is
providing. Right now, all of UBSan is disabled for syzbot builds because
taken as a whole, it is too noisy. This will let us focus on one feature
at a time.

For the bounds checker specifically, this provides a mechanism to
eliminate an entire class of array overflows with close to zero
performance overhead (I cannot measure a difference). In my (mostly)
defconfig, enabling bounds checking adds ~4200 checks to the kernel.
Performance changes are in the noise, likely due to the branch predictors
optimizing for the non-fail path.

Some notes on the bounds checker:

- it does not instrument {mem,str}*()-family functions, it only
  instruments direct indexed accesses (e.g. "foo[i]"). Dealing with
  the {mem,str}*()-family functions is a work-in-progress around
  CONFIG_FORTIFY_SOURCE[1].

- it ignores flexible array members, including the very old single
  byte (e.g. "int foo[1];") declarations. (Note that GCC's
  implementation appears to ignore _all_ trailing arrays, but Clang only
  ignores empty, 0, and 1 byte arrays[2].)

[1] https://github.com/KSPP/linux/issues/6
[2] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92589

Suggested-by: Elena Petrova <lenaptr@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/Kconfig.ubsan      | 19 +++++++++++++++++++
 scripts/Makefile.ubsan |  7 ++++++-
 2 files changed, 25 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index d69e8b21ebae..f5ed2dceef30 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -22,6 +22,25 @@ config UBSAN_TRAP
 	  can just issue a trap. This reduces the kernel size overhead but
 	  turns all warnings into full thread-killing exceptions.
 
+config UBSAN_BOUNDS
+	bool "Perform array bounds checking"
+	depends on UBSAN
+	default UBSAN
+	help
+	  This option enables detection of direct out of bounds array
+	  accesses, where the array size is known at compile time. Note
+	  that this does not protect character array overflows due to
+	  bad calls to the {str,mem}*cpy() family of functions.
+
+config UBSAN_MISC
+	bool "Enable all other Undefined Behavior sanity checks"
+	depends on UBSAN
+	default UBSAN
+	help
+	  This option enables all sanity checks that don't have their
+	  own Kconfig options. Disable this if you only want to have
+	  individually selected checks.
+
 config UBSAN_SANITIZE_ALL
 	bool "Enable instrumentation for the entire kernel"
 	depends on UBSAN
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 668a91510bfe..5b15bc425ec9 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -5,14 +5,19 @@ ifdef CONFIG_UBSAN_ALIGNMENT
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
 endif
 
+ifdef CONFIG_UBSAN_BOUNDS
+      CFLAGS_UBSAN += $(call cc-option, -fsanitize=bounds)
+endif
+
+ifdef CONFIG_UBSAN_MISC
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=shift)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=integer-divide-by-zero)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=unreachable)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=signed-integer-overflow)
-      CFLAGS_UBSAN += $(call cc-option, -fsanitize=bounds)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=object-size)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=bool)
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=enum)
+endif
 
 ifdef CONFIG_UBSAN_TRAP
       CFLAGS_UBSAN += $(call cc-option, -fsanitize-undefined-trap-on-error)
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120010636.27368-3-keescook%40chromium.org.
