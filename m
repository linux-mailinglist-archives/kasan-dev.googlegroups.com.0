Return-Path: <kasan-dev+bncBDA5JVXUX4ERBD7DQTFAMGQEARXWN4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id BC887CC1EDF
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 11:16:48 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-430857e8450sf1690390f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 02:16:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765880208; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ch3/Z0us3j4Y7dSCAdz3PWz8oPF3dRRe4eO7YQlFbdZFUb5Xg2mKBezGtcV8j9i4CK
         XCcX0l3SHt0Dcpf0ODlmUvQapNHTUEuuopjRm6DxF++RiDY2TEOW4kVpTIPhpLSssbc9
         SNKHrdWVW0PL0icmryCJRvGiiXPnp7PZhK6i09GUMVFtpjtxR8OhRvp4u0lHlQdSdIvN
         paE0o8gIdDdNx4OkWzsxWNpx8fVyWTorZ0vUsD8VcuOCjF7AzEu3GlP7MxYJEDBglQxZ
         tFHl8Q2TKxuAfR1c5OoSShTG5ozpsDpWlpu8bIEZ0PLYOUGiRjmRrpaWlwXPdGRo/iC6
         t2SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=N4yfci1cHI+2jC6rI+M/LtG4GTSpa8iDyu2e6UpMdeY=;
        fh=KR22HWA9fGkVqeDcGWsMpptSJ0JyxjNzdfGnfLdtoFg=;
        b=S/QbEIY3DXzy6HyvZjaiZPxEj3/kANpXrzI5fIu/vuRd2hDd3FBMbZAsayc1JxfrI9
         QL2b3X/mb/lXJ8R/QL2SpyHPX2oNie+KADOBov2kWj+xubajW1Dpk0hj6JeGqT7VOoW0
         UR86imxFfmWjbUK0ymt9dr1yuG2IE3ZNETTHXui81GwvT7522uUlwveM5npzXqwGoBS4
         8n3I42EkCqkPW1ArCFxhV+tnjcRdKfiOMX12tZjjBXTN6700JeF65PPdZe94trFPbyMt
         m67ZpJP/3qRpqDtwUuBIuCVQb19Vq/yj5uMxs/nb4KCy8FmvMIVQWD9FpcMfWLbf/4LQ
         U89Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EGgoEppn;
       spf=pass (google.com: domain of 3jdfbaqgkcuuqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jDFBaQgKCUUqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765880208; x=1766485008; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:from:to:cc:subject:date:message-id:reply-to;
        bh=N4yfci1cHI+2jC6rI+M/LtG4GTSpa8iDyu2e6UpMdeY=;
        b=F7DDyGXcopYp2pNYn1ziTQ1peEwkCSZVOa0a/s8AUl1LlOPhIccDVFDTriABhsGlWC
         C6f7hg2BIij8zJEBpZmNxrRab0cRQWjObHoAlbkbsIE8/JQiSbqhbnfjFMzcGVJJDKYG
         HCk/AQcpesX0YOAqYCK+3P7BUuVbWQgN3GnF9HCMUW70V82TEl27zbDpiIgSmQoxWJWl
         XqchW+Vja9zyTt2CnzsvVcR8Og2hJtwmiziCorYdXrypO5S+YVlj1e2UuwykXg823CuI
         Eax96U2oSAgR1swq62D6x7MpmeLs19esjaEG/Ju8vll+u5m4qYbp+PjL8Nqh+tb2e28k
         nP/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765880208; x=1766485008;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=N4yfci1cHI+2jC6rI+M/LtG4GTSpa8iDyu2e6UpMdeY=;
        b=rdww7pf/mgMF+UfHkqFdPOqHHL41epbjpMGm/itq1350nik7wRbyNA/hR/EN12y0nM
         cM0z8gf6UBHqB8vBrpArdtDJe5c/pgyJ42lnQS4Zidn/i+ME0D4iDAOAxEBnRliVKFhj
         ETPh4eo7fABkigA/82NbUC4gm/kpnpZMRW7SGPcdJA8UZutPP+HrAfPlfbNelMRU+AdX
         9Jdlgi+PT0pTa+VFvTWNHW9rpz4yKMvU9ZlRlAycHfcdEUeG/4nTQmZ4k21VEpMnk0A9
         wNPU91IlezVT+rwTNzlEvW3IyMVmt5RrWpAA07R07bocLjZCWa/NXnmiNVsanSNzC/mT
         d3LA==
X-Forwarded-Encrypted: i=2; AJvYcCVeOZl8Ht6ix1CUQZCDKSI0sqO570TlsfmkSbrsQJavvUhNR82DEuDiS2ODzPLnVYo8TvkUMQ==@lfdr.de
X-Gm-Message-State: AOJu0YwfDz1h/DhomTK04Bat1WNJXKR/TUG3Kbrwu9hxK5N+DBKcLDTL
	ggodRTpM+j30GJ+pLMThFy9uj39w2edHzmRCkqKX/psGxE/wSg6Wphco
X-Google-Smtp-Source: AGHT+IFK1g3++KKs7JzqZM7ZY1rjt4FTqOfTOhHOZefplN6kN8b74kAt51TLP/PrJYyfvWBQjueb5Q==
X-Received: by 2002:a05:6000:402b:b0:430:ffdb:e9bd with SMTP id ffacd0b85a97d-430ffdbeaa7mr5281997f8f.10.1765880207812;
        Tue, 16 Dec 2025 02:16:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZV5ewbR4oIMditYUpu6XlrgIKGLSVcDO7oHILkdGjS/A=="
Received: by 2002:adf:fdc2:0:b0:429:c426:e680 with SMTP id ffacd0b85a97d-42fb280a88cls765312f8f.0.-pod-prod-00-eu-canary;
 Tue, 16 Dec 2025 02:16:45 -0800 (PST)
X-Received: by 2002:a05:6000:4007:b0:430:f437:5a71 with SMTP id ffacd0b85a97d-430f4375b2dmr10314449f8f.13.1765880205132;
        Tue, 16 Dec 2025 02:16:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765880205; cv=none;
        d=google.com; s=arc-20240605;
        b=lMOWOKAxB+D7dMbs4EYlHH3JjTuCT42BCPxrsyyOAMsueZH3hbSqskMnDPMeKefh4Z
         /7jYxcaNRRpVk47A43zg7THAMuskd4Okw3ToTVweuE1yQmTuILITm1nAg4hboUBpHoWB
         LXuoVaMIxf0jvjqXQDaC/OhDcT2GYalXQ5GIfY9IiUAZECsCK2IJNSFQgz1qhWDRPrwT
         9RzCo22qwO7V/KurUXsZdyqUMkS6FnDyzySmvxGUOvoz0Ntp3ywW7+bdSR8b3nDa76z1
         RELXYVic9DZR3yK+tfwmoZXkGY0o6hPC5idYaT9TtRlJ3gufruXLTqXryuKypXy0q8Ml
         SBeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id
         :mime-version:date:dkim-signature;
        bh=SlEUOGv/EDetzTwSEetx6NPNK55ugxU1ppzq0yQMVTI=;
        fh=x2ubLsttaGNDEohungEU+QxSNGIjpxcBkXhQGHGw3fc=;
        b=EF7SJb1An9087KXQooNW103k583h/5iHLiuAbBCqjYP27NIr9qY+Fp3mS9wct4Q1cC
         FCZCh6q9+C3FCNCUuSZGV765lQDTnyOZwzzD5f7DrNOpjzcbrrXYX31HhdFPjzrCK8Kg
         WD2K9aCJMYFRBVKszlCQ3xv5zk8ojjuBMUsoDZg91buHimjgRsCs3WeAuzMG4VFuAD3a
         +P9W+T45omHcLczywPMr04+E/QEci7KnKcs3+ilqb8PjjN5OW/ctxXQzdyYM944+viWS
         rCftTXGDWgiaJkYO2iZsQXURiEI6bOtHzKD7lawNiHoqI4zHHsDJ65xOuy+VTiJ7ftLF
         4Qjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EGgoEppn;
       spf=pass (google.com: domain of 3jdfbaqgkcuuqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jDFBaQgKCUUqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-431065d936esi23526f8f.7.2025.12.16.02.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 02:16:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jdfbaqgkcuuqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775d110fabso31860915e9.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 02:16:45 -0800 (PST)
X-Received: from wmbjv26.prod.google.com ([2002:a05:600c:571a:b0:475:dfb5:f4be])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:3b86:b0:477:9cdb:e32e with SMTP id 5b1f17b1804b1-47a8f8bd865mr152390625e9.9.1765880204557;
 Tue, 16 Dec 2025 02:16:44 -0800 (PST)
Date: Tue, 16 Dec 2025 10:16:33 +0000
Mime-Version: 1.0
X-B4-Tracking: v=1; b=H4sIAIExQWkC/33NQQrCMBCF4auUrB1J0kRbV95DXNQ4SQdqUpISl
 NK7m3alIC7/B/PNzBJGwsRO1cwiZkoUfIl6VzHTd94h0L00k1xqIXkDzoQM5AfyCD6QT1MEoTU
 3FlEpbVi5HCNaem7q5Vq6pzSF+NqeZLGu/70sgMNB1kY1ptNHoc4uBDfg3oQHW8EsPxChfyNyR azg/NYq27XtF7IsyxvFNED0/AAAAA==
X-Change-Id: 20251208-gcov-inline-noinstr-1550cfee445c
X-Mailer: b4 0.14.2
Message-ID: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
Subject: [PATCH v3 0/3] Noinstr fixes for K[CA]SAN with GCOV
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, Brendan Jackman <jackmanb@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EGgoEppn;       spf=pass
 (google.com: domain of 3jdfbaqgkcuuqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3jDFBaQgKCUUqhjrthuinvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

As discussed in [2], the GCOV+*SAN issue is attacked from two angles:
both adding __always_inline to the instrumentation helpers AND disabling
GCOV for noinstr.c. Only one or the other of these things is needed to
make the build error go away, but they both make sense in their own
right and both may serve to prevent other similar errors from cropping
up in future.

Note I have not annotated !CONFIG_* stubs, only !__SANITIZE_*__ ones.
That's because for global settings (i.e. kconfig) it remains a bug to
call these stubs from the wrong context and we'd probably like to detect
that bug even if it could be eliminated from the current build.=20

Concretely, the above is talking about KMSAN, i.e. stuff like
instrument_copy_from_user().

Other than that, I think everything in include/linux/instrumented.h is
covered now.

Signed-off-by: Brendan Jackman <jackmanb@google.com>
---
Details:

 - =E2=9D=AF=E2=9D=AF  clang --version
   Debian clang version 19.1.7 (3+build5)
   Target: x86_64-pc-linux-gnu
   Thread model: posix
   InstalledDir: /usr/lib/llvm-19/bin

 - Kernel config:

   https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f053=
7e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt

Note I also get this error:

vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR: =
machine_kexec_prepare+0x810

That one's a total mystery to me. I guess it's better to "fix" the SEV
one independently rather than waiting until I know how to fix them both.

Note I also mentioned other similar errors in [0]. Those errors don't
exist in Linus' master and I didn't note down where I saw them. Either
they have since been fixed, or I observed them in Google's internal
codebase where they were instroduced downstream.

Changes in v3:
- Also fix __kcsan_{dis,en}able_current()
- Link to v2: https://lore.kernel.org/r/20251215-gcov-inline-noinstr-v2-0-6=
f100b94fa99@google.com

Changes in v2:
- Also disable GCOV for noinstr.c (i.e. squash in [0]).
- Link to v1: [2]=20

[0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
[1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7790d5=
4df@google.com/
[2] https://lore.kernel.org/r/20251208-gcov-inline-noinstr-v1-0-623c48ca571=
4@google.com

---
Brendan Jackman (3):
      kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
      kcsan: mark !__SANITIZE_THREAD__ stubs __always_inline
      x86/sev: Disable GCOV on noinstr object

 arch/x86/coco/sev/Makefile   | 2 ++
 include/linux/kasan-checks.h | 4 ++--
 include/linux/kcsan-checks.h | 8 ++++----
 3 files changed, 8 insertions(+), 6 deletions(-)
---
base-commit: 40fbbd64bba6c6e7a72885d2f59b6a3be9991eeb
change-id: 20251208-gcov-inline-noinstr-1550cfee445c

Best regards,
--=20
Brendan Jackman <jackmanb@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251216-gcov-inline-noinstr-v3-0-10244d154451%40google.com.
