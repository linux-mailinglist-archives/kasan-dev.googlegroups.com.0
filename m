Return-Path: <kasan-dev+bncBCXO5E6EQQFBB3O2VPGQMGQEQS2D4QY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cFpzJm/tqmm5YwEAu9opvQ
	(envelope-from <kasan-dev+bncBCXO5E6EQQFBB3O2VPGQMGQEQS2D4QY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 16:06:23 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39949223707
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 16:06:23 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-41555e51e94sf14158987fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2026 07:06:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772809581; cv=pass;
        d=google.com; s=arc-20240605;
        b=FDjC92m4I2HVE/J1AJxj00ReUXUPBUagP8oIkB38t67knL8SBI2H16pEZn9IkZkecl
         8SP35XY0sg7Tz0FiX0frVyvK2loT29xaIT+g/WO5JBSJdc84G2xO+PPaB6P0sMGw0hyE
         UvSCC0zNOLij47fuoTRzIDy/8o6uH7z22rdFrhBxdR7MPyre1K/7FjiG4njN/EkUpC3n
         FilTJO1BS0eObFPISpBCLeR5QgGxiyqJ/FtZmZCVXe8uQuAKnS5spkABUO2t17OS5MNi
         IMPwxQEP2n2jmM6dvSjLBzUSk+VesJJwyk/Enm8g9z0mz0OAnJBnU29VuVSaq0kzLGt2
         9kug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=pNtwhfeCnvmqITEklXFK0EZEWRcvkpEbqxdnhv7bNcw=;
        fh=SmzkBcRRA9a728oiBECpu+XavjnS2AjMaH3Th6qvRYY=;
        b=Y/wrUTk2UsozgvoIiRAQ/qcIJWFR7u60HdzC5QcNh/wV+yDDrIoV3MqSrZN2y024ci
         Zzmj0ac6bU5TLl8aijsaMfuEmo93lCgRXxowUWYeW0V9t3lzK9hIBozkeUqqsJWzwAlf
         3+iGL31gwC87gpQevgimky1ziPiRvvMr9G5HEoLSPsWOYR+KBdI6AgX41R2x+jQEYFAF
         ShPe+niK0DaCpHlnJySaZqB+PdOv9WbdiQT5g6VcI8TjW3YILhrXQJob6O0+QZRzeaRR
         NZA8964gJASSIHvda8XLxENkqU/y43eXc/9ylf7Iou60vdVQF3LltwyH8CEq+So63Of9
         846A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IDpuoWA5;
       spf=pass (google.com: domain of arnd@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772809581; x=1773414381; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pNtwhfeCnvmqITEklXFK0EZEWRcvkpEbqxdnhv7bNcw=;
        b=mrohptj/VzHJQMSfC3gkFicqel9VFbeZ/kzVHL+8ktpjf0d47bxh6m2NoxLPAW4OzW
         8VbE7q3Bq+Lc1N1aJLqzx8I1ifOqfCmgy+vcZxaeAMqvctHsLOOE2o5bdXelmGPyXyGg
         VFSjPLnJd/Ojr+oS/lLNcW4fNxfJVwuBbQlrvKjdawPCes4gJArML3OqVOmQf2dFndfJ
         n51FazibKm1AJkATXUL8YaRoi7tocVoHtJQnl/Bgg2BUu31qcjg8kZITtE/xOR1mVseb
         1AvJIrCFGggFFwpzm7yRVo3aZEHirc+q+pdZN/bm3RhP7cZ0/rbpjs+axy1pVT/bcQCu
         2uIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772809581; x=1773414381;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pNtwhfeCnvmqITEklXFK0EZEWRcvkpEbqxdnhv7bNcw=;
        b=n5WVMqs4O/JsY4CZk92ESU/2yzLBmlfLRasOY8fA1v+bgzby7UtqJlWJXCDTCcCmmm
         dgL34VCJPnau+F8A6yk1KtzzV+znM8Ky3pk4mfDSVWMd69qm7WDL2ArgGj0966K4tVbS
         TwMR/f7LU67VwfwKET3jPWfhHLFOXkx3Sm0gHFoTcSLJqVxkzAbruQW7lnCVVjMc8PSO
         pcozB+fGZhG3rDaxHzfDQzcu/4LvO/tWsfHcF6B9PtSEUJWBrjbV7Y/5aqcCGGPv1vKu
         PEbr+oxB+6vF8zwNP7xEHAGJMytiQcyY8BpNsvz5X9y3HNh6atVjYFrFJJ8GV7ihQtFQ
         eVNg==
X-Forwarded-Encrypted: i=2; AJvYcCVreFue5W0dDFOOnjQ1gEaGljzMuCTonKgbCzF0Ut2aC0t0cmV+t7zA/PKBxReTfvv+Zlx16A==@lfdr.de
X-Gm-Message-State: AOJu0Yxs8Wbfa8azdmdL9mCiO3ij9WqlQHKWxgb6vJUfmqARtYQ/+sE4
	KwguChzCOziyAl6kv0EfrkUXCxIz6a2xsy1LUeMzeNxIGi79PlqH4fNP
X-Received: by 2002:a05:6870:3b06:b0:404:33e1:3cc2 with SMTP id 586e51a60fabf-416e3fd15aamr1407650fac.13.1772809581534;
        Fri, 06 Mar 2026 07:06:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fgwb3LsxPzzc1EkYSxywyh0bj8RiPuOcYn5/oRglZdHA=="
Received: by 2002:a05:6870:7093:b0:416:7216:f918 with SMTP id
 586e51a60fabf-416be67a8bdls1014370fac.0.-pod-prod-04-us; Fri, 06 Mar 2026
 07:06:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzX057p3tkR8DW7mwygQKK8lErpgTcLz/763EaydZyqKyWqfrWiRE4+uSb/A94jAiYIDVJL1dUBR4=@googlegroups.com
X-Received: by 2002:a05:6830:7105:b0:7cf:d7fe:fa2d with SMTP id 46e09a7af769-7d726f93e84mr1787319a34.17.1772809580560;
        Fri, 06 Mar 2026 07:06:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772809580; cv=none;
        d=google.com; s=arc-20240605;
        b=eNLudnUI9FELgpFQZns7QK2cM9mvB+8cIgKvc+lziIH1+5RouVyTrg5SVb3Um3e3iS
         sGHxxUiax73gn0fU/Yqm/tZft4zV0YUfCjcVV2v0iL7QRTp4pIoiXn/xeM9hw8rLEaOt
         p8Gtoe4WMnphBx4cwcSiu+nL+s42X9HWnKsmhO/7cHS28G/fRSPnTZZujDmVntnvjukm
         C0xDZHC9OSl4DH6n9hxgDlRPBfU/mE64rsAlJUPSKOIUOB98udYpptmncj7OuTM51iI6
         L6eqj/GPDH9dznkFwkptkbgV/FXWeWqEMgoUZxhnRJmIIClDjmFZ++2KpM4iKZC+8ZH9
         IXVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5OXHFGLVMYDPBk1hCgSpXNluW+8RpRtlpxBsYPciWtY=;
        fh=4aeMRbl6/blodqReOxWF/CGLkCfiRvz58f+SBjTCJkw=;
        b=g8hjtkzNapZokXFt8b4ALBxT4aNXwDLppxnECYCpurhje5Jn7+EO296CT4uBOOjpZj
         UFa5qQKaEWwcx8nec1p/5mpu+EFOoeXaDKOSziJfE+g4ZItrg5437RXaJkRxq8oWK3Bl
         vJhDJm/M7dFS6YHkiDgvZeWUuIYKgwK/KgYUS0ND/Zi4pkE+t8XTBTUnOHkto3mpRR98
         6GbI7wpcBAA+n9DVR0soH9cAsVzgcIodx8c1aH5f9QPhiijZFRXCUVlZVxstzIKsfghd
         Mgg8xReNlrx/aAyaeQgiLXhsaK9wue3FMu7LV3Ht9IUCB2pedcIBePoWfybyL6M4w7TY
         pryA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IDpuoWA5;
       spf=pass (google.com: domain of arnd@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d728d0a395si53018a34.5.2026.03.06.07.06.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2026 07:06:20 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id DE6CC6012B;
	Fri,  6 Mar 2026 15:06:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 84CE7C2BC9E;
	Fri,  6 Mar 2026 15:06:16 +0000 (UTC)
From: "'Arnd Bergmann' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] ubsan: turn off kmsan inside of ubsan instrumentation
Date: Fri,  6 Mar 2026 16:05:49 +0100
Message-Id: <20260306150613.350029-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.5
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IDpuoWA5;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Arnd Bergmann <arnd@kernel.org>
Reply-To: Arnd Bergmann <arnd@kernel.org>
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
X-Rspamd-Queue-Id: 39949223707
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4864::/56];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCXO5E6EQQFBB3O2VPGQMGQEQS2D4QY];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[arndb.de,kernel.org,google.com,gmail.com,googlegroups.com,vger.kernel.org,infradead.org,lists.linux.dev];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[arnd@kernel.org];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,arndb.de:email,mail-oa1-x3e.google.com:rdns,mail-oa1-x3e.google.com:helo]
X-Rspamd-Action: no action

From: Arnd Bergmann <arnd@arndb.de>

The structure initialization in the two type mismatch handling functions
causes a call to __msan_memset() to be generated inside of a UACCESS
block, which in turn leads to an objtool warning about possibly leaking
uaccess-enabled state:

lib/ubsan.o: warning: objtool: __ubsan_handle_type_mismatch+0xda: call to __msan_memset() with UACCESS enabled
lib/ubsan.o: warning: objtool: __ubsan_handle_type_mismatch_v1+0xf4: call to __msan_memset() with UACCESS enabled

Most likely __msan_memset() is safe to be called here and could be added
to the uaccess_safe_builtin[] list of safe functions, but seeing that
the ubsan file itself already has kasan, ubsan and kcsan disabled itself,
it is probably a good idea to also turn off kmsan here, in particular this
also avoids the risk of recursing between ubsan and kcsan checks in
other functions of this file.

I saw this happen while testing randconfig builds with clang-22, but did
not try older versions, or attempt to see which kernel change introduced
the warning.

Cc: Kees Cook <kees@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Makefile b/lib/Makefile
index 280a71e4f813..3e1eeefd9832 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -306,6 +306,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
 UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
 KCSAN_SANITIZE_ubsan.o := n
+KMSAN_SANITIZE_ubsan.o := n
 CFLAGS_ubsan.o := -fno-stack-protector $(DISABLE_KSTACK_ERASE)
 
 obj-$(CONFIG_SBITMAP) += sbitmap.o
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260306150613.350029-1-arnd%40kernel.org.
