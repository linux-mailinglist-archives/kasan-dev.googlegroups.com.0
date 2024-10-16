Return-Path: <kasan-dev+bncBDAOJ6534YNBB7VUX64AMGQEW2FJ3KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A8679A0E10
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:23:43 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-37d39bf2277sf2320890f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:23:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729092223; cv=pass;
        d=google.com; s=arc-20240605;
        b=XZE/9DHiX19UQcfTdSrmihFrJPR0izwsF8jtepg+puCE7dKUO0i4266lINSGUFGU/M
         XRmADcQ0ktkOatBVCJ1shWNvC3VC1EeydilLLwI9Boanb7z4txOB57qjLWir6uLzBoIG
         yJR88CGcK3bBwSYUvk+PIux74FLnyKWaWLtPgAyvTdglpL819mUL0xV/0M23Ln5uSGTE
         4bkIfYBXFIHcFVhImCM5R85JAPNuNMJcRCUp8Tmsg/wtmDrEebs1cMm6U5EfvY01TRvM
         iLBg8UKFsBK/Hepyf05JRcxMy+oddheTOM1tkOVKnTNOyqDhM+TVVrZ9oPP0an0XWAGE
         skEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=aC+XL1VSzvvsuQaWqPR6bohd1s6421N7l4GawKCqlCc=;
        fh=pc3WsZugWF85Uej4QqBrOMpXdKsSCzp8iKZU+8qWJrs=;
        b=ZWvmhCdu+hBc39vx2OXvvwFElzpCTkewhMWXWvP4QjSU2VCmlNvVbh/zgja385Ecb3
         0ZSDQLxV1zG0M+K6hXmZTDGjvaroEWy1JsG3qwXLkCe+sDl57RqjIpFTJVnovy99i4t2
         0Vcuru03Pl/DWQT7jk+4S0jMH2BvoyEcrN5VzrZbigIf7lClSmus31XMP5+212VxD1OK
         oV2v72O4wnZR1LOx6D7wjCd6H7yuFjrLVHAOxhl527h4izylEMSMw6CEFoFGnfsMMB5S
         UMwjaQ1sfbFz+wrT87N9qWqkK0gXjyWHYM1JdbiCV4o+oiFTZdpzv0x3fmKUyAkeVqQJ
         GibQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=b2s2grq9;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729092223; x=1729697023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aC+XL1VSzvvsuQaWqPR6bohd1s6421N7l4GawKCqlCc=;
        b=Aa73OEzh95gxENEcgm7Apz6o1NKehFdFmnW8kf8QwVIh5w823+Y5LKUL0+cTzuh+d6
         Y+G3D7ckOWSE+4Ok8Yj90q5taaGV8A3IqRf/9lZ65Aio5wgWInLWFyL5TTWO9BuetTot
         Z9FGAmW3WzWK6g1c//wbwyZwMTp7GdWsdqE9ybDUa8NqOFD7uT1HBcT36C5TTOETcNeC
         wclxT6hEqA+vIcyjF6DkytMdr43creXpky4OPXfXrov9CcqR7YvqcapNncu3EYpHRREs
         Ox6AkWZh5XwbXQAYlhAyrBXHT8ZwuARR63ysiz0NlDb0qPRSvTSqyx0PgbuOi/own593
         H6Ew==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729092223; x=1729697023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aC+XL1VSzvvsuQaWqPR6bohd1s6421N7l4GawKCqlCc=;
        b=lMWVxQBTVdu202PikovMWVPxRYLrZpCuJUN3kJolL5PaZMR4MlckUeBE/YxTpIHtY4
         eAcGNwsuJ2/cbtL3ghKRlST8RlxwnRM0D4olKdqCos2n9k/dHz2K/lFkuV4x6xRYnXs9
         Ddvy7aVvk9lquPkHxw3K6h32ocC/ahBRUvBM1+2Z+ingCZQC0mmC5eqCwbPi+aZysUXS
         OvtlXPlRBijJwHRD2mJA2GMST0CsriqHUKK+QnyK0AbvNK2uQeyb1qxTVfYhm7woumiU
         HnnqwcTuYUxSHe5S1MuWi/4+AtKI15RUQvUR6GsyiIa8m8WWnOWi1QuuZNCDov3+wHvo
         nJog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729092223; x=1729697023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aC+XL1VSzvvsuQaWqPR6bohd1s6421N7l4GawKCqlCc=;
        b=jbqsKPk7dhQF9Xgl9etismHFJiYZZ4iWmE87tzVfau31j6d/+wefaeTP8HFH++M2Ip
         GI4xoXVJtLoJ8prWku1eLnsCgLHGgHC/jwAX+D52nYU7VPKrv25aGx1oM0Ocv+XJSuUD
         9PTsOMrS0eJkudN3IKcu6sC2c7F/VHBK0mbByGZMfWh47WH1igZH+s09/gqZCvfqNW/0
         OXgp14RVz9KPa4eg3tlM3MSSNKCr+4LgqdYeJYgoaUqoXSyD8er/6FL6K+MHHpN90zeB
         tW/LEJLBBh66im9nnsRdxQpIObTn9ZUqOeYl6g0fOqtOvOrDJPQeaPfXIjzFXw3V36dy
         YDPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbG+qtySx5P+YITcSl8lnrUsR/SzHKsGZvl2kGB9W0ftGiiIE89W7bS3pvm2o81iS6hNCWuQ==@lfdr.de
X-Gm-Message-State: AOJu0YwsuH4pOUwLQAbbd7VM48SRRgFcbos8zXp7Grt9qt8bPEPXCtH5
	VvJ8V+ygzb2gNGddZiAb8fYSwFyPjedBI5kl0cDiP2HyqY/WgeC1
X-Google-Smtp-Source: AGHT+IGfrcaGmXH/IWeUglAY10qeYrJ0jx02uYbQzvtnkgY4J8PbrALkn+VAshSHRymFSsGJlGNIZw==
X-Received: by 2002:adf:ea45:0:b0:37d:2e78:8875 with SMTP id ffacd0b85a97d-37d552ce636mr13883382f8f.56.1729092222191;
        Wed, 16 Oct 2024 08:23:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f68a:0:b0:374:d287:ec15 with SMTP id ffacd0b85a97d-37d93518d8cls6446f8f.1.-pod-prod-03-eu;
 Wed, 16 Oct 2024 08:23:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwERI9byGoQk8mrgf1QCm/Ve7vtDotjrE6osCq9PmwKwlCck6zoO+6o3LjzrUO5AjRK/L3YQfOX0I=@googlegroups.com
X-Received: by 2002:a5d:6452:0:b0:37c:d1c7:a0c0 with SMTP id ffacd0b85a97d-37d551fc572mr11598955f8f.30.1729092220336;
        Wed, 16 Oct 2024 08:23:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729092220; cv=none;
        d=google.com; s=arc-20240605;
        b=N9W9R3nVfypHQkJfKPawrOp8Kw84WMnhbZjtgdnUY3zNTqml+LUV2XVUGI7ce0FRFC
         VB1qkWrtHuv8Ld+l/8ENYwPFXsQCYUnENKRggeA//RF1vOFjXfwXSAOwXJQzrg/yKsS7
         H8T18CGYcJA+/132VK+4e73ekTbur+ATWc8ZoFZbE916l2pC0hEc8OqyrS6F8XuMHwm/
         GyTEzVl7ATuWVtzZCMGjJWUkgRfwo+onY9FA+diielp415smHQzV0g+bAmJzkp68NhsI
         ph59MfIlKltc8mgVPMjVsiuwKzgF6kSuXiA4eUsAbFBba/rpAONMOwBVPWqzplZfjKXR
         68/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cY/0jnN+gTIzlQ25L2cKGw8awZf9M+TjmgtDbkXUG4k=;
        fh=RS72PqTomGl2wM9q8DbSJZVLHAAlK5qKrMLlr1+3E6M=;
        b=aCEgo+uvcSdWJ6yisyg6lXCVvbWpcW6gh99/3howJDpHQvMj3kW8XDyldJdbinrGzK
         oHC49vWeA9PdsNUWR8+1FveSQc+jydtFcPVPZykxouz323gKKACf5mDu4Ocm0jWYM4Ex
         7lwi7eRHg+oUjmHgw+zJ5GnRxL9ZewPYlihpVxj+Y5XKeM/ybr+XuktVwvcY7xaMBVm0
         58Ouhj9fhGReWmD+8brZ6Hr9JcsVzIYKZCwPx3l7GtJM1xwcuzwlofIFqjpywvcXx5KG
         iVscoz5XIPLpCA5OgzEgPlv+C1Qk99BdWVK6vd2JnV0OgyYT0G6KoACo+W6Uz3eCFjwS
         /WMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=b2s2grq9;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d7fc4017bsi85895f8f.6.2024.10.16.08.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 08:23:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-37d5038c653so4275904f8f.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 08:23:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXFgwitwxagm78o0Yho8BIjlFQCQtoDQpuTQfSzXQBMtaJZqMiKs73lKatz+egkHAhK5m9pPA+DTeA=@googlegroups.com
X-Received: by 2002:a5d:63c2:0:b0:37d:52bc:72ed with SMTP id ffacd0b85a97d-37d551c9775mr12197578f8f.14.1729092218149;
        Wed, 16 Oct 2024 08:23:38 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-37d7fa95dfesm4592545f8f.63.2024.10.16.08.23.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 08:23:37 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	glider@google.com,
	dave.hansen@linux.intel.com
Cc: x86@kernel.org,
	akpm@linux-foundation.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	snovitoll@gmail.com
Subject: [PATCH] x86/traps: move kmsan check after instrumentation_begin
Date: Wed, 16 Oct 2024 20:24:07 +0500
Message-Id: <20241016152407.3149001-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=b2s2grq9;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

During x86_64 kernel build with CONFIG_KMSAN, the objtool warns
following:

  AR      built-in.a
  AR      vmlinux.a
  LD      vmlinux.o
vmlinux.o: warning: objtool: handle_bug+0x4: call to
    kmsan_unpoison_entry_regs() leaves .noinstr.text section
  OBJCOPY modules.builtin.modinfo
  GEN     modules.builtin
  MODPOST Module.symvers
  CC      .vmlinux.export.o

Moving kmsan_unpoison_entry_regs() _after_ instrumentation_begin() fixes
the warning.

There is decode_bug(regs->ip, &imm) is left before KMSAN unpoisoining,
but it has the return condition and if we include it after
instrumentation_begin() it results the warning
"return with instrumentation enabled", hence, I'm concerned that regs
will not be KMSAN unpoisoned if `ud_type == BUG_NONE` is true.

Fixes: ba54d194f8da ("x86/traps: avoid KMSAN bugs originating from handle_bug()")
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/x86/kernel/traps.c | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index d05392db5d0..2dbadf347b5 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -261,12 +261,6 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	int ud_type;
 	u32 imm;
 
-	/*
-	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
-	 * is a rare case that uses @regs without passing them to
-	 * irqentry_enter().
-	 */
-	kmsan_unpoison_entry_regs(regs);
 	ud_type = decode_bug(regs->ip, &imm);
 	if (ud_type == BUG_NONE)
 		return handled;
@@ -275,6 +269,12 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	 * All lies, just get the WARN/BUG out.
 	 */
 	instrumentation_begin();
+	/*
+	 * Normally @regs are unpoisoned by irqentry_enter(), but handle_bug()
+	 * is a rare case that uses @regs without passing them to
+	 * irqentry_enter().
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	/*
 	 * Since we're emulating a CALL with exceptions, restore the interrupt
 	 * state to what it was at the exception site.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016152407.3149001-1-snovitoll%40gmail.com.
