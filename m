Return-Path: <kasan-dev+bncBCXO5E6EQQFBBJFPWOPQMGQEDRCD7GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 99F56697C95
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 14:01:26 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-50e79ffba49sf206564347b3.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 05:01:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676466084; cv=pass;
        d=google.com; s=arc-20160816;
        b=aRy/FHe8eKWmW6s4WZHNHpFDaOduM6Es3x8o4rqpiqrxDWeSl+dOGOnQ9aVXepN3m/
         MBRqrglzg0WNYlSIfIgMSVdqF0DtlAfW5PG/OW8YOv4JNLkGN1D6GUuAUgCWEoLcowFk
         U6yqw5JLItC74hHNGeiOJnhVDFXyekm9yRcWCxqHOE8k37DiGL882w0lY2gPzyrWzUS6
         PrLoH/5YPgu8Svkq57sMWisDqOu1/PwUJb3Vnen5vtP8r/JnDAg5E35f94CnJsi7Ch79
         lbReqdrsmv61//1TZr4kq8Mx58TJKmgL5toJqh/wskw/nte2KlaFARGSoWrZKE3m4xxm
         HMIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jLzrh6d+OBHVg54FPBvPKbteZdp/hQOH4iwkryIHvn0=;
        b=vmt4BI0kdv9Gy3AGedBQ/9ZMadPZZVHrAQ6gB2TnOZ+LyKgZwXd2PrOqk46jJ0EsBx
         aCB6fAZoBzjjMVVn7f4cTht2aAsEq2LcMnja/fbQacq+z0Fb8GKBq3x+ZBoHg3lGUTj0
         K5AjUAfKDjVncXsC4phaC5259qMeGQ/091/JahX3W8Gk2DIg4axPVJPDTVFh7QRm2Kk9
         6IdQWSjp3m/fwe6lmCBNxrj6rOPu7OXEQbj3GF0L7Pb/rqqnW+R7ViSPFgbrgIc02u+l
         VCFVP0u5fIQdgLCvhWBbYBqwp+2DofZxyiFQ/56BiuobkCaEqnC6uZj+RU0lA0AA8Bkd
         43+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=trjIqlwZ;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jLzrh6d+OBHVg54FPBvPKbteZdp/hQOH4iwkryIHvn0=;
        b=MAP71kp1vyuBTSukot0C+Qt8iIdWeDvs0FsKnWSUAiWd9J6hgNhX0tCt93i6Ll+aQM
         0hHDU3C+75tkMJv7UAgeK4YLNjuVwZ2yDTMNZ49umOVd+vYmuadFyYlFd4aSnn0mdoGS
         8jf4wuEYodBEFptSGeOLtnZ1eil3AV5iuquxRcdF2gQbUsmvTtE1Ro64FeVUXdpY0E8q
         4pWTf8GFv1u09dQ0Pqi4Rb9rWdaFyB9FQzCUy6Ug9V7oepJkjvl9bStqZK8NV8373jlE
         FF/k9NsHUOXqq2sO7p8vdTchWqBS+4XRCAOsAWPVQpAoNtpfqIoU+UGS0H73zvgseZEo
         tzvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jLzrh6d+OBHVg54FPBvPKbteZdp/hQOH4iwkryIHvn0=;
        b=6wjRuYxzXH4Mbj3rl2Zi6ywF/T+n4CeKwar8+1Zfs60OWZQKXdtZ/M6cwmdTWZSmd1
         qB0cMbdZ6RmnO6+ZQMnjhCbtqgSciVxrrkiuyKgfmjlH7qwBA+UnUt2GAG6JIPMAEkc4
         ssh5Fxl1OYDBpmPuK8qq3UqzJnuBLOFh2hzJts79qVDCYW3yD7Ph/a6C/1PHZDQ0Ns4j
         4yNdP4V+nNSe4CP/g3V9GWAtMXWHJ9NUo43TjfppczCxbCShfCGCMz0suSjyI3G4cpU1
         CIJpTb1oK2N0mNlckFrHckzuIMjOu8s9grNK1va2XhhUUh+1TMzFRDRmJYJginHgUB6j
         s/mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUWq8wTUR2pqYZxVxfYtXdQdLMj9HuEWtwmr/S+dbgvaRaw92TT
	17hMrNrrGLuV5eCNkkPN+IY=
X-Google-Smtp-Source: AK7set/Nxw7VM1VAVewjefY8MDY1+s93k8251f0ge4fvcSm+qD91oyI3mgkn0d6eV+IwwuR+I9eD/g==
X-Received: by 2002:a25:ce51:0:b0:8cc:a1c:3712 with SMTP id x78-20020a25ce51000000b008cc0a1c3712mr169571ybe.565.1676466084435;
        Wed, 15 Feb 2023 05:01:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:f207:0:b0:506:4723:b3e4 with SMTP id i7-20020a81f207000000b005064723b3e4ls11082249ywm.2.-pod-prod-gmail;
 Wed, 15 Feb 2023 05:01:23 -0800 (PST)
X-Received: by 2002:a81:48ce:0:b0:527:e0a:35ba with SMTP id v197-20020a8148ce000000b005270e0a35bamr1686431ywa.1.1676466083753;
        Wed, 15 Feb 2023 05:01:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676466083; cv=none;
        d=google.com; s=arc-20160816;
        b=JnGoMbtWSwiqhYZx8vOcnHvHqUcdT0Pal3zFZH/HJg9hwfrdUbH1xlaHaqUnvsTVV4
         tYgv/NhFUv7Ba3Fk7MlXUelSutfjXkBq7z2mjOj+HY9v5ykbQJzXnz08173MbiTsInwJ
         tyD8EDj+Kb9E4yLoGfm+gLH5vLce02udk7wejx9CxKe54oawmRgh5lQQOWX6lOUUWqcB
         sJ9Xi17U1H2qDfV8A1OLHBk593OHq5EBPu5gLfywzuZyQTcmEdHfBoUfvC+hVaj6tK9j
         8MjPE+5rb8B0b5HDnUwrK98f0C9xwFo02VVkpM9VvcEPHxEnWW538acjo+NdZYkILTau
         NS2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TmXc5XX7mQ4tyyYhso+an7R7TS3SjE8ukS97BSt6G1c=;
        b=NY4y9pMz5ZKZ0xIr3StAUdlSxDZyoLKCly2prwxZh58mNHvlpyr6CtFBQWC8yopTLx
         Zm3QPI59AVVbMISsrGrLkcrXdhTwyszCpQqYbDHrTt4XCeLqCu1O2V39sRSFWvlNrkF6
         +VQ/hguGqEoy59Lz0jzYpPU+xOK2DQRkc5YfS4sKClyNe3wlXzlLzZrfFA88CUpV/WKm
         R0bWJZzAB7o92fbzaSoy9amubsPAZHIF7ezHoeRNWElkivI0rLT8Tr6qErt3ITPwPRfH
         hZDorSKq4CBzSSOYhEC8qKob+CzBJzylTXZThCC4Z0QKO0WcxPVMrdVnNUtn/fPBgeyz
         DaoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=trjIqlwZ;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bp2-20020a05690c068200b0050646ae9a2fsi1023926ywb.4.2023.02.15.05.01.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Feb 2023 05:01:23 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6E9BE61BA6;
	Wed, 15 Feb 2023 13:01:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4813DC433EF;
	Wed, 15 Feb 2023 13:01:20 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/3] [v2] objtool: add UACCESS exceptions for __tsan_volatile_read/write
Date: Wed, 15 Feb 2023 14:00:58 +0100
Message-Id: <20230215130058.3836177-4-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230215130058.3836177-1-arnd@kernel.org>
References: <20230215130058.3836177-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=trjIqlwZ;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

A lot of the tsan helpers are already excempt from the UACCESS warnings,
but some more functions were added that need the same thing:

kernel/kcsan/core.o: warning: objtool: __tsan_volatile_read16+0x0: call to __tsan_unaligned_read16() with UACCESS enabled
kernel/kcsan/core.o: warning: objtool: __tsan_volatile_write16+0x0: call to __tsan_unaligned_write16() with UACCESS enabled
vmlinux.o: warning: objtool: __tsan_unaligned_volatile_read16+0x4: call to __tsan_unaligned_read16() with UACCESS enabled
vmlinux.o: warning: objtool: __tsan_unaligned_volatile_write16+0x4: call to __tsan_unaligned_write16() with UACCESS enabled

As Marco points out, these functions don't even call each other
explicitly but instead gcc (but not clang) notices the functions
being identical and turns one symbol into a direct branch to the
other.

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Acked-by: Marco Elver <elver@google.com>
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index b0b467d9608a..da52ce861cc2 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1237,6 +1237,8 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_atomic64_compare_exchange_val",
 	"__tsan_atomic_thread_fence",
 	"__tsan_atomic_signal_fence",
+	"__tsan_unaligned_read16",
+	"__tsan_unaligned_write16",
 	/* KCOV */
 	"write_comp_data",
 	"check_kcov_mode",
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230215130058.3836177-4-arnd%40kernel.org.
