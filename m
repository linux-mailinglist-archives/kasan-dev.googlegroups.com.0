Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHFNT3CAMGQEXLX6XMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FDA4B13E40
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:22 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553b5884201sf3191760e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716382; cv=pass;
        d=google.com; s=arc-20240605;
        b=bmQTtPXhFh3pIT9drXXf76s/5+FvwUihXpVk6VTTnxSvT22FH+bK6YrGgGVf0biQO5
         nrtCavhNnEiMucnlg0/RDfYzwP65tZPEPzps4MucciT/TqXIW2yBHLhgrtJnLdmzyNUM
         RBEocP1j51jbW4tQRUqJisVnEfC6fE/IyEugvtqJj4DewyfM6xEF7xIhU5vqLfJv8mAF
         bWOmqEtbyXvhSKsgATg0eSbnH6dcwTWQ0kLdyigli0O7yK9rjys/gM/LFWI2/bo9SbiD
         jSCzT1+knIj1NQijciCQrvgyeYsE+rvPKnyzDpG2nlSzMvwpO0K/7o301pR58KyKQxXo
         SjFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=bG83OSf4Rdv+/yte6wX1/W7dNcXNBye3nG6Sx+i0IWU=;
        fh=tMpQaqwfMj/D7ISKdJo1jWJFBPD2Ccw91DzYzugT61A=;
        b=Xh1VHyScpc5TGRfU5agq290orOfXbXlHW0shfknfRZy4aEtSzLqJTNncantTsBQolZ
         wT1da5S64fA+pAv0JEhCNaBPqhvjp0FyXsMDGjqZIFpCWQrER+bJq8RdY73iaSKz9ntW
         fhNIUGfV7xfI39rYclFnMzISXWP3RTbBXGykezhAcsxEM/vxcAakmeHG5b62MqwwAltl
         6FiV1lxlM1QVolm9bgHm+mwhW2s9x7tm9441Fae2vWfD+vgRaf0ENOgPix0dlehHxbeO
         N8KGRM9raiWsR+YEkOW6cWJHHm+Vya/kYF5WehRNaBxx1p9wPzp6T8xzuTruvugbJrVR
         xxdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cWf+9HwY;
       spf=pass (google.com: domain of 3mzahaaykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mZaHaAYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716382; x=1754321182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bG83OSf4Rdv+/yte6wX1/W7dNcXNBye3nG6Sx+i0IWU=;
        b=sZ8ANoupt5xmWGVoyfWZtud0Omz6Ki8M+TixXNVuVHnChtxAvgxJMnCP4qraroe9fb
         kHmp+a0QgjCtWN0NgNL8QIcSoB8pzuuIWqnzn7CE8LknKTe6ks7Kj0dCa5DsWiK8LAXq
         SM32PyEzr0pNFWFGYV95gImnRtzGQ9rYFlFOuGkwb+8WCH/TQReOZdCkDeESkrIcL1YS
         z3lXrDxr3d94APHhQtK4JVS1NQdLYel4OM3Sr/1JlMg2OvpzzWOXYfl0MswbFwZ3IxmX
         DoSp90Nht+dswpFzl4ypaP6cwxRKFxTI4oeBW3chv+Y/rZVlO3/YNDid0hrJd5UxzcCY
         i0cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716382; x=1754321182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bG83OSf4Rdv+/yte6wX1/W7dNcXNBye3nG6Sx+i0IWU=;
        b=PSRD6K4MOlIx6J44nfy6tqMHELfEBXC5MwEMM7S188+VUE1hkTqXCZPpb5ftEWMHxQ
         Kcyepgr/u2ZWGwrvZepyX4MbIrbilGdneT0Z/dTcaFCWRz7+5ebRIprVgRIWAgJG4sHh
         oQjqSupGnE86dcp3ee1bZ2ReM+hsd+JPQrUh8fDcNpQASzbV7wbQResQMGocaXyErsAn
         VtDHCrANYJFY5ocmCQ1SVEDcl3T3/j5hW37Hdl1NMduH+vG2+tyr4uTDp0JennoYcb96
         x5k9k780dSECeHVYjHbosiCMtosFktxkwJF/oIPxGK0ZL8+Zut2ElhKGEkd52rJ6sysZ
         tMXA==
X-Forwarded-Encrypted: i=2; AJvYcCVw5LmKTc6sjBU/TSCEK1Bx1X1PxuwE6+ydQLL0lRO0V8RnhCkx69mgkVvpJHZw7oktUU9/PA==@lfdr.de
X-Gm-Message-State: AOJu0YzQDWMOo6qDH1fjr+jUu8WujnfxliP+BuJQKkOlkPoER5brk8yK
	RFPZgck7JEHDsGZK/ZqUY+yST8Joi/l1MYvek2zoaoMlVr9XbesGMaS1
X-Google-Smtp-Source: AGHT+IFQ3VCTSQN9VIrXYfgH2Vz0iNauNwiWSSaRRFDgd6hhlCs2wi1z5jkb5CFmquIvdNrXlpLHuQ==
X-Received: by 2002:a05:6512:b24:b0:54f:bf00:6f38 with SMTP id 2adb3069b0e04-55b5f4c1c74mr2728172e87.45.1753716381484;
        Mon, 28 Jul 2025 08:26:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfH3rNTTD7XwXUT28LAb+63bdVtAvRxo4dCY8rFM8cz5A==
Received: by 2002:a05:6512:140e:b0:55b:600d:1cfb with SMTP id
 2adb3069b0e04-55b600d1d98ls665981e87.1.-pod-prod-06-eu; Mon, 28 Jul 2025
 08:26:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlNi7AJsGc43ffpFRaUaH8ohIQixiM5kkbNS8GGfjba0g8Lb1vPET12Gkn1a7MLNArbTe2Y1wXXGI=@googlegroups.com
X-Received: by 2002:a05:6512:1392:b0:553:518d:8494 with SMTP id 2adb3069b0e04-55b5f4cef6emr2640292e87.54.1753716378463;
        Mon, 28 Jul 2025 08:26:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716378; cv=none;
        d=google.com; s=arc-20240605;
        b=TmNWivewwedCSJOnu9sA7HMq2lWZDA7Mf9Y+KQ38m3VkT1iAD5AaXPq0ek/2NvbK84
         Rmj+pj9qPlP25heAHcD+IECx9eN6CstKFFry3zzQ/ZUzu3cefID+Ffm/JpDgCtALdnQi
         okzAwQ6Y68B9mUsFydnD6Q1OmD0/Q6yCRDgdcVF6qalYJrp9Cq7NZaO/WMQrMaMIqhbY
         bNy0B3T/59PlqCpv2U3yClSMhyODq8OfbhT480x+otuFLivB0waKaGx/T5Iu5Ba06Vmg
         DqnCYWz57jvbrOjFJ313I2II2TTIIzl/L5+PiNPJLuGnVRGzCvxihrSsi4UJRFqTa42q
         6DNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=uFjnsgZ8ZjgFIrgBqo3fRpKhi5jRt02tyhhsiWaGr2M=;
        fh=XWSmCCtvhnpmKkXM8E6zJy+VBgI+ApgKlImaqyxG/pc=;
        b=UrkmU0AfT3RtH0scXecd+pRC5f6J3F1lLAkbOm5sDOCdqNlVQoY/9QyNhQAO4Kjd6z
         96TIqHBWj35asy6tTZKu8N8p2kZH5h2UxrnQTu35Skpbscse8unooRYafj2qmQozf4zX
         sx0pgUSPPSMg5/1n4HumS4HTYcENfnzec2tpwmKmRmfHxUxEDbzLxwuXNfxgzjzAJsN5
         rkY65+ldfxRRu5JcHjRX2T1MYg0wTALS8j1/LMDOmH7GFuordY7YwmbeTSR7SosyyoTr
         lgKBgNc9r/GM9u519dcochi0xcZXA6PfBqanc9tnNujm0gifUyTo3KLC2BYjZLwETPcP
         oGhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cWf+9HwY;
       spf=pass (google.com: domain of 3mzahaaykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mZaHaAYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b630bc62fsi66958e87.0.2025.07.28.08.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mzahaaykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b78329f180so1435448f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVG9vOXhplXiLK1HVXoUAfjbWx3XCuOo8v7tukFH+NoGLoltXHBpkVCTZp3x9Ux0jTsd0TX3JD0WDM=@googlegroups.com
X-Received: from wrbfk2.prod.google.com ([2002:a05:6000:2702:b0:3b7:844b:17ae])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2083:b0:3b7:662a:b835
 with SMTP id ffacd0b85a97d-3b77671d144mr8757417f8f.6.1753716377790; Mon, 28
 Jul 2025 08:26:17 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:46 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-9-glider@google.com>
Subject: [PATCH v3 08/10] kcov: add ioctl(KCOV_RESET_TRACE)
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cWf+9HwY;       spf=pass
 (google.com: domain of 3mzahaaykctasxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3mZaHaAYKCTASXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
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

---
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
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-9-glider%40google.com.
