Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDNNT3CAMGQEDDWELNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AAF5B13E37
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:07 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-33212a4abd5sf1180161fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716366; cv=pass;
        d=google.com; s=arc-20240605;
        b=XVCFYJsccPYximaXrjeOlvOhMfXJpojVN7QOwIctsBV+U3n7idJXZXEt2O+DjZQKXr
         MkMi1Z7eMl4lQOzUfC5O+hgwOxNR4twYtL6ZHIF5czSn1HLy16eAzK2hLD/eqjxIRGBS
         t/9dJiSKIpAZNBbEwfGxTcSDCAVRDUmZKvmIjHOoC0y/z1v+Rq3ZRIhlNsdF0rTT8lAy
         Di9An0VOF8Wo+fx7LfqsqUcHrWqiCJrg5BN7L1u9aEAQw4iheZrxlQ50xHXbHBVvH9qS
         wr3sAdE6Vsklw2VCt1J9MaHdxzx9r7VqbGUsN1ijiS63EVY8PgX6MdDzzL22c3xUe67y
         p0pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MaFuueKdlLTGKiczBh2Aesc73v6hhTeOt6LVl5C9eaw=;
        fh=MVL6nyoMu5y2f/u4MHpn7/wHEH5I+GIEaoaimmQVpb4=;
        b=Tbvo/7z3mP8uO6v0Co4VsOjKgaRO69+rmbl6BW4sqTY7nSRLCQKJaEJEhi0vQKo+bm
         ABSfm7XVcD9/sWtyJd7BvFmHIpWU1KCXRLF25TC5XDjJP57iBiWQR5MyV6vWPaKuPbrU
         3muHF/psfmj9zZSTEtbrBJXGJhT3v+D8Z2udNwb2numstp+w/LuP007WMev3PjV9NYcm
         4jU3CuUYae5cbtnFXiKwGHYDYj2/YqdJII8zBqnYYuQpMruZ+lHjpvmc2WaLGKEaT2An
         sXZHEdW+tXA9N27WmMMP7LaVkOPrCABM+piMgSPa5BWQOvxjd3/3Y+ORSmD17Mn/Ex+a
         ZqtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FhfzOvFo;
       spf=pass (google.com: domain of 3ipahaaykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ipaHaAYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716366; x=1754321166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MaFuueKdlLTGKiczBh2Aesc73v6hhTeOt6LVl5C9eaw=;
        b=h9aGsLLt6i5ctr7l+JppwbgUqHE37nBDI+9GhuWUFjwPGfrkI7aGIhJweayegW/fPm
         2jaBFGnLS6L62AjyZ5RVluGIlQCAgHuq8L9W6l0nFuwkQIBrPF2xhcd4SSXloDiEY+Ak
         rYJqmjfW3F4L6OWj4GKaWCJAHoERlMY7oUIHy/2jNyDpkdpwJJ9LBe14mm82tLhvB59U
         lJ7QfTEEdYsL5HaafoeSCl8sXVXAnWoRyE0bcyEYkCHbKev8Pu76do4+Jw765Hm+uwZJ
         3hj9Hg7Yz2sdMNIIKvyaqjY8HV8ghfrLNGSmRRYuqwqD2EorBkcMAXRQR3uejLJYToFN
         VBLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716366; x=1754321166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MaFuueKdlLTGKiczBh2Aesc73v6hhTeOt6LVl5C9eaw=;
        b=PFXzQ78OMmDNPKpWDcytGxULw0ZlqqmFj8luLmoo5PrHQlRSZrraH9SLrsr0Ejkl99
         6zyQqWnxNo+eSYJfbrFenXzExkcYuB2dYabVKErd2WtJx2lBA/uhAVrJAQGpB54b4Vhn
         c6gKBQNJgDPKLV7WIiHzXk/KQyaYtt/UQ5cVogDTSymuUk0wOGfVN1Q/NkBjpzKhsbqm
         RpMSlLJCMKlX9k09T/nh8WBGilniNdVMJwZ3S0DNFovJM2fqE/R1AHghmEEGqiFGYyH0
         LAYRS77FBGG5LbLPMvGmndQ3IhKa7JPd9iAl8mm9trTwhCqitVPXJt6kVhUYpWiFuz2U
         oV0A==
X-Forwarded-Encrypted: i=2; AJvYcCUfxlVrLgZ5amzerfnXkzLbTeXSSXgCDr9X8yjt6QEinTqvTcSPIvNkTgKkU5S/HuJzf3oVYw==@lfdr.de
X-Gm-Message-State: AOJu0YzU4/NoR4J/jIiTaZ4BiKNubeqrOCs+0/+3Exj3GNDwKKBR/Vm8
	jUXvAmE/tKrcEkH3m20MVeFsFUeNVnaTUMDnI7rHp2foGVGUPhxoy9sp
X-Google-Smtp-Source: AGHT+IEltmvSjkmHQ8PDHD8V5HrSGZBn6NSZeKqCBty9JilJkABFUS0iSUEjNz76SwYvsGBAdFZYPw==
X-Received: by 2002:a05:651c:408f:b0:32b:c74e:268 with SMTP id 38308e7fff4ca-331e25b5ademr26168571fa.17.1753716366396;
        Mon, 28 Jul 2025 08:26:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZceQB2O0Cr48JFVgyTINnM9vO0QNysnJNj2Jna+gLbhmQ==
Received: by 2002:a05:651c:4181:b0:330:4b06:2cc4 with SMTP id
 38308e7fff4ca-330ddc1aa56ls3930931fa.2.-pod-prod-00-eu-canary; Mon, 28 Jul
 2025 08:26:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpr9J7zrikawhEHU8eZv7M0zGB99EqnpFvg3Tz3Vt89jNRug2EXm0DQ5h9UzfTQvlCsC+9wKQqNGU=@googlegroups.com
X-Received: by 2002:a2e:8a97:0:b0:329:1302:a521 with SMTP id 38308e7fff4ca-33215373bc0mr22211fa.2.1753716363375;
        Mon, 28 Jul 2025 08:26:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716363; cv=none;
        d=google.com; s=arc-20240605;
        b=QoBCBC6Bd3s4cfvW50NXpNLukA7GEBEcaQB3rMA9x57ZJDnZfk8pjNg7Og3LjRLlh8
         pQFDj1dGfDZCgng6wUAb8nAzUr9poPvH92SFhKUNRbOSgesiQl3/KutFlBEK9P4sxMzC
         DJBuvGLONgOeDfvDh5gYssoGc399YOs+wlX+ovT2NriM8pqiYd6AxD3/WAW2G77vI+qw
         bG6aXCIe8xIfJ2Si7MBv2Ty1lZQZ44q7fwoeDaN/enSLLj4wcCbJxhIKHd6izfeTCIne
         YlJtYbTQ9yDhpcOsqqzUBGWAdjkxiiKVIO9/C55VbgDcw5AkrXdoFd4TFIbD5sr3bR/n
         tcsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=85Dq+0aWzQbqxgpA60NbQvRp1U2h0O13hIt4+o13Fas=;
        fh=KPnxeBxhexXs9B7RU3/QpAA6N4ylXnz1sChWZo8XO44=;
        b=UXouDZ09yf1YhXQT0Z/6++oruPv5wfa5FpK/9zWU3ubHkQmt63CHokXrngQaexStG+
         4h4SWpof+yComKKBfLPNtuj6rqyBnh6ZSjh+Rs+9RYzPWxYm4+LsCGubDI9Kf9wptjZz
         NrqFeXptKdp7IH79S5WnhSZLTuW+y6k5YX+t5xHMNHgFjR88lcPR7ALdAcqZFfeRy19s
         YDDZ2CXFMJGMiJ0nweAWHtsJjduhDOtD3KkwidZIoLMTMVanr2FwJO/aF+NbDp1XKby5
         Snsv905FkVdqa01L2RrFhne6PfX7lIXb7kDhentc+SlIA9LVqTnAbJ+vPp6rfDaWBah/
         eEFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FhfzOvFo;
       spf=pass (google.com: domain of 3ipahaaykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ipaHaAYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-331f41ce796si1836721fa.3.2025.07.28.08.26.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ipahaaykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b788d00e26so589089f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcOTYJ00tMqrhK9U89kEF6W8tCOLVuYUt3JK1t5b8lBSlZIEGJ5hRBQ0PdPJnAw1RigWQcLSlW2QY=@googlegroups.com
X-Received: from wrbeh10.prod.google.com ([2002:a05:6000:410a:b0:3b7:76ea:26cd])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:4009:b0:3b7:8d47:6f82
 with SMTP id ffacd0b85a97d-3b78d476ff0mr666355f8f.57.1753716362501; Mon, 28
 Jul 2025 08:26:02 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:40 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-3-glider@google.com>
Subject: [PATCH v3 02/10] kcov: elaborate on using the shared buffer
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FhfzOvFo;       spf=pass
 (google.com: domain of 3ipahaaykcsedifabodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3ipaHaAYKCSEDIFABODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--glider.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v3:
 - add Reviewed-by: Dmitry Vyukov

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
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-3-glider%40google.com.
