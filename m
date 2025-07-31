Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4VRVXCAMGQEVM73MZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D0AFB170A5
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:19 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4586cc8f9f2sf1372295e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962738; cv=pass;
        d=google.com; s=arc-20240605;
        b=kBspEyaB1LXPwdCkXKvPS7IkJGn5GfGy3X/eW9fVXjPcphlIGgFbdougNHa7AK9wTw
         DaZw4ji/oW15/eSXzVmYjAJ2IhhgNjbR3Yvp7jBqGYFWXMyErlzoApyRTtfp+Ssasqgk
         n0tGGxEpu8s1HgoGVpopls+ok5HjMpLW0KKPtAxIo+l7lknJ4KEOf9Vs7IgIbAjLVPGf
         P6WWeUOHyaOZKzwUfOnNcMOdx5E01+mFn3VtToz/qLwR/ADh6qBf30kD76gK+xlKyKqn
         UoVsQpZS3Kvwl2Y3fZVJAcV0rpgaKQe80Ciu9hV2hY6sJT+6S0RrxRI/mPmWnDVH+TaE
         b1MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=jTJfvGMJhPc45sE9MNMu+m+jjL6A9DIIq+gKRa4rrug=;
        fh=QbMiXx0DwcbTbsZLnmM5WfaCrmLSCQnPa8ZE7KEGrgY=;
        b=i2sQwuRucyhZcw1enX0jlJwttAVeNUHYiuM2UqH4Lvi5keBOiEU0XEt6sjALzdnOP5
         imK7lymjcPGhtYrfA2rRb4+SRB7A07zMLwioug95iR4NZNRvqGcD0gyIy9A/Lc5xe50v
         f14Iec8jpZu/MM2qaXtA0vNsvG6wkpk6W09qjV+JyGFwgWd3KxEHWzqhdhZOVQw7Hb9k
         mHcExnzlq2Y8YfC+UoGm9cLNjF2lwm7e/+UncyRfhHy11xJ6VWjdcPojWHYx6KbW0lKt
         Q+j8dp6LntBm6QMUILGeUvYcTV0JPqxdLS/bhn/mkFJ+H4+otcTCT36GBnPDNKYMMhTn
         w6Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UOkQHcl7;
       spf=pass (google.com: domain of 37lilaaykcrk5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37liLaAYKCRk5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962738; x=1754567538; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=jTJfvGMJhPc45sE9MNMu+m+jjL6A9DIIq+gKRa4rrug=;
        b=d06zK0i4Gg+rNSemNHDN0WUeQiheo5KAIfXCq7R8WkHLgPo4QqfdNOgKfwkp0bGTPv
         MUlRzJqGunT85lYYLf3BiFMxhZYzSfs02Xai3bjwbg39XXxKFl5izTvyiruxyNrxPeWC
         gD94xuqCjne/IBc2xkFA9bapLl/9vpHnJhLaNGRW3zTXKqO8WJ113M9xvjWgCxTF2gOU
         4rZBSlE7ijVOrsUaqsC2NdxKZplQVYf7Mf3qiRtvrwcvykuTOCj8RNG+k6g1QSnwCJ9T
         vMmYJNhKfcbn0syKRNGDIUJ83IGIk5D1xXNYU03yWDk58T4G6d4ia7uAQoNEQH/pfnPM
         uVAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962738; x=1754567538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jTJfvGMJhPc45sE9MNMu+m+jjL6A9DIIq+gKRa4rrug=;
        b=c6ifdcETgV8md7LahzaMbmWOZQ1AsZFzbC+DP6tnlQwrk64Tcc86baX1zT4x2lbx+c
         Wm7VE/Ebv6G9RFwmqByUiACpVvXfZvU1sRtWXpGJHXUALhZNjQNM7UiwZQvSnBD1b17J
         /6omctlUzmxGQCEJm8L3Ljwbui1n3RVfAe7bjH64Gy08QT/PfGSu92H82eucNnJsTThP
         BYzUefiRnQRCaKZizVkgpe8RJfwxkLFuhRP9gegR63a13AJRI3eC9SA8EG7va94TJ4rQ
         UupFauJItolytACG5oYStmM1cDG1QzM+ucZ+zVOGScFu8l/tvak//xLKYDaPDg56rVQV
         YKbA==
X-Forwarded-Encrypted: i=2; AJvYcCVUq/7KRxuotriBTwEXJlQUBP98z1sR4PN3xhcRIK+6bRUO5y/8SwHHa7ZwNCCgu8HxTqkDoA==@lfdr.de
X-Gm-Message-State: AOJu0YwKX12qVe8w5KwGOw6gweQ8gzN+CJJtRTa4hyBTzZVmJimyqnUU
	lcEEpuz88hGsQDseVnU6pVW4n2xO3VnUu4LmvNqkOp2Qy9OUHjfe/M/x
X-Google-Smtp-Source: AGHT+IFRYFlO7hyl5XxHJ3vt2cW16M8gdiIN+Kzspm0M1i+cWuOCIi0KrB/g1E02ZmoNhTBhAV2yDQ==
X-Received: by 2002:a05:600c:c059:20b0:458:a559:a693 with SMTP id 5b1f17b1804b1-458a559a846mr9944605e9.18.1753962738673;
        Thu, 31 Jul 2025 04:52:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZejMXrlyndLiBVAbRw2537LUi8GDFlmS/mVwfkwGA3PRQ==
Received: by 2002:a05:6000:400d:b0:3b7:8ddc:8784 with SMTP id
 ffacd0b85a97d-3b79c3cef00ls272420f8f.1.-pod-prod-03-eu; Thu, 31 Jul 2025
 04:52:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+RA26dwVk+KYFmv3aOwPm5xwaLl5Nc7Ao6oS7Z19TdF9ZMz7T5rv2lvqKJVkFKRuNwHe8s/55kYo=@googlegroups.com
X-Received: by 2002:a05:6000:401f:b0:3b7:8832:fde6 with SMTP id ffacd0b85a97d-3b794fb6807mr4958994f8f.13.1753962734789;
        Thu, 31 Jul 2025 04:52:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962734; cv=none;
        d=google.com; s=arc-20240605;
        b=E7JtHLKGo0JFulmdn6QvyVPSRzGnVNnHwu0D3sq8p+4NMN0+Q/VxgDAVL6unxUr8rX
         wnfHRta7es9L1zXZDfh7l73m7CO2Yp8v8IBxgt/44F5uZJoMCem5t06X8YSgZVLj3MLo
         QyEe0U/yybZC/qKj9MiRUTC3tm+N7ha5yZC+JLWUn9I9Moag+HQQ+8afvuH0VzNDdYzG
         GaZ+GOPU5SOMs7kHDBbTb3PrfEta55b/gzF3cTgdlkcjFnEt6HflEUSq1mqNQOEvrmVk
         uenHnBjgtZw0TvAMUwKmHOAd8YlKp8+bmjlO3LJ+pif42dwL/8xUZZlB9r+yYmv8Uh5h
         gO3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TiC3uM7/D8NzErdvh0SxeDfKJcSB6iSbAQ3laEPvArs=;
        fh=GR/m7SHrHBS9wuM/aqqTu/0dN4kZ4DoZnjrQza3frjI=;
        b=dMBEYh45vX/gPcjLAXqe0EXFQQL51RwRgRKSdckWI3fZ9dTA0jSBLs7+ibbPvdPMYL
         Jsb3V3F3vgLRtYX9opr4+Sv2AWIQYLLEB8ZF7U9pGSo29coGbbDGNEiJuS4qYk0+6IYZ
         rGFkxTY/WRt8OpHk/A2RlzviUycbuAypvP1rID8h7bHOe9NotIkaVfQSDHBaATdwfc1j
         S/JyouuO4fQWGBxGFBzpfjZhQbSyZhQ+m8KWCEYko/+39Y9an/v0J2QK9KnXqZxHACgJ
         yyIgAGcmfj8j6M58Aw2j5KobMjj24VZqYPwv1oBVgNtqAtAyEQV3bn6jIf0LWLVcm4PM
         /V8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UOkQHcl7;
       spf=pass (google.com: domain of 37lilaaykcrk5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37liLaAYKCRk5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c339ca7si44765f8f.0.2025.07.31.04.52.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:52:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37lilaaykcrk5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b780da0ab6so435331f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:52:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNy+o6Tsghs0IdI8VFDIVBFPjzIG/ERIBjwnyeaTbsUTzjnD4CAaO/pkaaLmxW1JBY2mOmkQWFrcs=@googlegroups.com
X-Received: from wrbfm13.prod.google.com ([2002:a05:6000:280d:b0:3a4:eef1:dbc7])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:26ca:b0:3a4:ee40:715c
 with SMTP id ffacd0b85a97d-3b794fb67fbmr6412932f8f.14.1753962734272; Thu, 31
 Jul 2025 04:52:14 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:37 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-9-glider@google.com>
Subject: [PATCH v4 08/10] kcov: add ioctl(KCOV_RESET_TRACE)
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
 header.i=@google.com header.s=20230601 header.b=UOkQHcl7;       spf=pass
 (google.com: domain of 37lilaaykcrk5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=37liLaAYKCRk5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
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

Provide a mechanism to reset the coverage for the current task
without writing directly to the coverage buffer.
This is slower, but allows the fuzzers to map the coverage buffer
as read-only, making it harder to corrupt.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

---
v4:
 - Add Reviewed-by: Dmitry Vyukov

v2:
 - Update code to match the new description of struct kcov_state

Change-Id: I8f9e6c179d93ccbfe0296b14764e88fa837cfffe
---
 Documentation/dev-tools/kcov.rst | 26 ++++++++++++++++++++++++++
 include/uapi/linux/kcov.h        |  1 +
 kernel/kcov.c                    | 15 +++++++++++++++
 3 files changed, 42 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6446887cd1c92..e215c0651e16d 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -470,3 +470,29 @@ local tasks spawned by the process and the global task that handles USB bus #1:
 		perror("close"), exit(1);
 	return 0;
     }
+
+
+Resetting coverage with an KCOV_RESET_TRACE
+-------------------------------------------
+
+The ``KCOV_RESET_TRACE`` ioctl provides a mechanism to clear collected coverage
+data for the current task. It resets the program counter (PC) trace and, if
+``KCOV_UNIQUE_ENABLE`` mode is active, also zeroes the associated bitmap.
+
+The primary use case for this ioctl is to enhance safety during fuzzing.
+Normally, a user could map the kcov buffer with ``PROT_READ | PROT_WRITE`` and
+reset the trace from the user-space program. However, when fuzzing system calls,
+the kernel itself might inadvertently write to this shared buffer, corrupting
+the coverage data.
+
+To prevent this, a fuzzer can map the buffer with ``PROT_READ`` and use
+``ioctl(fd, KCOV_RESET_TRACE, 0)`` to safely clear the buffer from the kernel
+side before each fuzzing iteration.
+
+Note that:
+
+* This ioctl is safer but slower than directly writing to the shared memory
+  buffer due to the overhead of a system call.
+* ``KCOV_RESET_TRACE`` is itself a system call, and its execution will be traced
+  by kcov. Consequently, immediately after the ioctl returns, cover[0] will be
+  greater than 0.
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index e743ee011eeca..8ab77cc3afa76 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -23,6 +23,7 @@ struct kcov_remote_arg {
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
 #define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
+#define KCOV_RESET_TRACE		_IO('c', 104)
 
 enum {
 	/*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index a92c848d17bce..82ed4c6150c54 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -740,6 +740,21 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		return 0;
 	case KCOV_UNIQUE_ENABLE:
 		return kcov_handle_unique_enable(kcov, arg);
+	case KCOV_RESET_TRACE:
+		unused = arg;
+		if (unused != 0 || current->kcov != kcov)
+			return -EINVAL;
+		t = current;
+		if (WARN_ON(kcov->t != t))
+			return -EINVAL;
+		mode = kcov->mode;
+		if (mode < KCOV_MODE_TRACE_PC)
+			return -EINVAL;
+		if (kcov->state.bitmap)
+			bitmap_zero(kcov->state.bitmap,
+				    kcov->state.bitmap_size);
+		WRITE_ONCE(kcov->state.trace[0], 0);
+		return 0;
 	case KCOV_DISABLE:
 		/* Disable coverage for the current task. */
 		unused = arg;
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-9-glider%40google.com.
