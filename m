Return-Path: <kasan-dev+bncBAABBW5PVKXQMGQEFO4TYZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B4CFB875D3C
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Mar 2024 05:45:16 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-365067c1349sf14734975ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 20:45:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709873115; cv=pass;
        d=google.com; s=arc-20160816;
        b=TArxRFqNKat+qu5DIkqKlx0R+VWzp2/xSDQSTdkS0hOgYeitfoRkvE0IfW7W/X+Hme
         RcjBVZydhNrv7dIpgD665tE/tUt7NfbNubAwi5QEafkqG0I/f32cf0CZTHG5ZgL6fNmO
         vmcdeNZCGklUpV4jiZbWwGCUfqaYXGY9fZ4/nBjlDHRst22IMY8KL0mQzjUBT2pxTusw
         WTZNn97tNbAsJoe+ccE9onC+Io32VvbYehIEo3d3IDO3mR/KtWD+CXlwSrQCGX5LXQSQ
         5OB1ejJLA+Mymu47hUV4U+h8ccRZXYorkGtUZmrGQ6MxYquT1HJsuLYclN7PQTaGsL4o
         qZ3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=qkdbtYJ1UbhcXhuOUkaSbsQbZ0eXagmG7U8R0k0QVpU=;
        fh=i39iw91+i8Kxr1fiGlXArS+fh2FiB+1RUuy5wgtD81U=;
        b=h+1g67F0/5TRF/5k3Pgy11/6dT0vUClKkxEuWrwQ3njrckCqhr++6vjr70FwFwAz3D
         2w6r2kfjSqD7CGbyblaNsHHviq+i1BvIgKonc1U/+FQAlILNoLRrCBqFI1mdgxScQuJT
         4ieU/aRpyl4NL0GEPPjnWf0x0gwP1wKu3TMi5L9qw0xfwzYkpvyM4gNkQGD2rnuLizen
         4NltKee9jfhcasaqfMkqNz7DCbXonlO6/VElOEFarxbrrbk2t4nnhwNdJu5bU9eVrhju
         B3pjmvuS6TddSW2OGoT1tjiGvxmb1ZBfTz8sddFerXL18z6D40gjws56yK/eXpk1/eV0
         x1Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709873115; x=1710477915; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qkdbtYJ1UbhcXhuOUkaSbsQbZ0eXagmG7U8R0k0QVpU=;
        b=QM/EZhg4tHtjjkvXXZ51Za0z+9en4KVGeBOAFi+oSJ7/JdprQZdrZz8HOtb145TvFK
         McmZRc7c1uEFH1baTnhxBqJCh2mO1LVuzdvIJsBOgHC/geza0YtSOOuaqD11ZtybTl3u
         kSVLgdwPyvhExFk/1VoVHuRXZATrqlgK2i/WqeZSeZ2xy0KEdSNEX7wi1VZudcsR7AyA
         KzVziGLp5Ec4ZWiZM3fBEyo3QBT9xOULob/WUarfdAebyl0zN7NlUSRpDiQeRJ+YOXsr
         EE7KR8Ncw8Vqqn6Ebr+9p8UusONLnSCEXwY7+s6IBuf0u3sZukpMPjbwszUbsN8bKc35
         rAbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709873115; x=1710477915;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qkdbtYJ1UbhcXhuOUkaSbsQbZ0eXagmG7U8R0k0QVpU=;
        b=iQ8xKvXZl4ZCxJrJY5Uyix1OjfU+5m553hNfBux3Z0N9NapZZCL4DIrZgZ7jPpTL4v
         UlEVLCq7Bj2fCeJSgC5AM/KuIR7/I3EpITeXPsW+nO2Qqxbh4fd4YsPvaKK4XY39E5YO
         HxrAXIiirM2dWYFmD+xkWr9ZOpkKyPjgqSUasXureoNvwxUCO1vC0aDntTUUpm8wwViW
         9OYeTUKb7jfw6N+PJq1m4SSTE9NqM2+iQO7CZXKWprHML1Scyi1yEQ2W3erxuz+C4dDy
         jFWLz46yr9UxepHCszI5Y6ae3/Y/LDr1k7emL9yFEmPRftKXZXZ4r/OHmWugbIZyXPqr
         otcg==
X-Forwarded-Encrypted: i=2; AJvYcCXDPz780MC6wzcr0f2FPGTAVzsVXTKkPCoP9tmbI7etCsPqaNqU/m6Sw9FH8IbQtx8zU3371X5uxpiubDUr2Oj4ebPnyPzSBQ==
X-Gm-Message-State: AOJu0YwWvicp9pl7u1VGmhhaBVlxArQYHM9j6LhoBtSIPegLgu1weSF9
	t0UsB18cKYcIteiovCT4pgbiAnGq2OZWgA4sU1xsjivfm8DpIxTO
X-Google-Smtp-Source: AGHT+IFfjUlUmpm1PjVvJZos0TeRBqTIBBdT24DCMpGtr98DjCvsuv/H9fFmnofScmTwnuErQHBkZw==
X-Received: by 2002:a05:6e02:b22:b0:365:a941:1b7d with SMTP id e2-20020a056e020b2200b00365a9411b7dmr22581377ilu.18.1709873115317;
        Thu, 07 Mar 2024 20:45:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d8d:b0:361:9298:e7d9 with SMTP id
 h13-20020a056e021d8d00b003619298e7d9ls385718ila.2.-pod-prod-08-us; Thu, 07
 Mar 2024 20:45:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0ZIuCISLVShCCzlOy2KIPNTI6guqIHqVoXT1zF4J64B1+3VFKSnkXeSfvAg5Ykngs1uAu562ntcUUqUISMjzPcJ51unotzCUltQ==
X-Received: by 2002:a5d:9349:0:b0:7c7:4061:1323 with SMTP id i9-20020a5d9349000000b007c740611323mr19220145ioo.12.1709873114598;
        Thu, 07 Mar 2024 20:45:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709873114; cv=none;
        d=google.com; s=arc-20160816;
        b=ecjtez9Bh0rMOQD6Eh+JIVLu8+0BO30tw4Z46U12mW1k/fhSgB4Vz17YhpwPMCe6nA
         b6Q3t/seiS9s9kAiUaMvm0b9xiFJpKt+uB8StElCx4RdVyQL4Sq8hdtGEm2Dkv9BYkDC
         CR53AL7r8DtsxVRG5QADdNCo6JAXSEy3+MOwAmoCrEBrXh5vkFZdKO/PBQf+ZeIh+Gw5
         OItxR8WV4lSQ7NlU2EQX1I5SMs2Z7WJ7Pm5+CK4QdAI5ssSY7WTvtTRKNh3REqRAfV3H
         C4PEBFrilCO6M/lMlKUid87mrYIE1z54/VVrvArr41M/jMfhyF0bZbXbcloj0JzYTdzu
         gdhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=u3+78WKm7Wv9LLMDEXD75GoMLVH3JHN+j8OLuM2yzmE=;
        fh=qXJK40/4I3pB8zWNaQc0dCR6bgUMOHrvivcKNMkJ2yk=;
        b=k+aXxb7pTbkXADlYHtk/MWQ4wmoEeA5TmxuE/z0mrmpldTCwR0O0k7TS9ICr7La4xA
         JcCFgOF1JEhHBiNGHGHqrg9i8pgiPfwtfleavx99rXyWisXcxjG2vnJ1SM8P192ag7k1
         4L9jIQbMuhEcVcW3NOJF27yuwpnPo5KMw2G2sJs96/CjZlahk1TsyFtJVaFWNy1MWP1z
         bvQoWmIGLG9sfH24d1eVsw5G8JknuaGxrfYjkMS7TDDdCt6mb11DxyoyGUYW/IA3HEvm
         53Z4Cs1tq4XJdvDeCWMCuGgjDJYkhU5JEU+FUNw4qcfsp41HLtW6Of4gz95w+FnvCf9g
         7zkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id ce19-20020a05660242d300b007c85fec43b1si494005iob.4.2024.03.07.20.45.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Mar 2024 20:45:14 -0800 (PST)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.163.44])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4TrYSS3T7zz2BfcD;
	Fri,  8 Mar 2024 12:42:48 +0800 (CST)
Received: from kwepemd500003.china.huawei.com (unknown [7.221.188.36])
	by mail.maildlp.com (Postfix) with ESMTPS id 28E4014040F;
	Fri,  8 Mar 2024 12:45:11 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (7.221.188.204) by
 kwepemd500003.china.huawei.com (7.221.188.36) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.28; Fri, 8 Mar 2024 12:45:10 +0800
Received: from M910t.huawei.com (10.110.54.157) by
 kwepemd100011.china.huawei.com (7.221.188.204) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.28; Fri, 8 Mar 2024 12:45:09 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, Andy Lutomirski <luto@kernel.org>, Peter Zijlstra
	<peterz@infradead.org>
CC: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Changbin Du <changbin.du@huawei.com>
Subject: [PATCH] x86: kmsan: fix boot failure due to instrumentation
Date: Fri, 8 Mar 2024 12:44:01 +0800
Message-ID: <20240308044401.1120395-1-changbin.du@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

Instrumenting sev.c and mem_encrypt_identity.c with KMSAN will result in
kernel being unable to boot. Some of the code are invoked too early in
boot stage that before kmsan is ready.

This change disable kmsan instrumentation for above two files to fix the
boot failure.

Signed-off-by: Changbin Du <changbin.du@huawei.com>
---
 arch/x86/kernel/Makefile | 1 +
 arch/x86/mm/Makefile     | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 0000325ab98f..04591d0145e0 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -33,6 +33,7 @@ KASAN_SANITIZE_sev.o					:= n
 KCSAN_SANITIZE := n
 KMSAN_SANITIZE_head$(BITS).o				:= n
 KMSAN_SANITIZE_nmi.o					:= n
+KMSAN_SANITIZE_sev.o					:= n
 
 # If instrumentation of the following files is enabled, boot hangs during
 # first second.
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index c80febc44cd2..6ec103bedcf1 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -16,6 +16,7 @@ KASAN_SANITIZE_pgprot.o		:= n
 KCSAN_SANITIZE := n
 # Avoid recursion by not calling KMSAN hooks for CEA code.
 KMSAN_SANITIZE_cpu_entry_area.o := n
+KMSAN_SANITIZE_mem_encrypt_identity.o := n
 
 ifdef CONFIG_FUNCTION_TRACER
 CFLAGS_REMOVE_mem_encrypt.o		= -pg
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240308044401.1120395-1-changbin.du%40huawei.com.
