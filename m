Return-Path: <kasan-dev+bncBDGIV3UHVAGBBTNJWSEQMGQE5WALMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 67EB73FBAE4
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:38 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id r4-20020a1c4404000000b002e728beb9fbsf10340882wma.9
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344398; cv=pass;
        d=google.com; s=arc-20160816;
        b=doxhdlWqxFzYqt6zYT7HF1SKsfiQmLoK7DP7SENlZ7Gnfe9C+U5up+9xPlZH5NVoVH
         cKmsO3JLptCPE5wkxIUbY9hLBp61v6W2pBTaSs350ysVqx46l9qDjVGsIESbOCZ176Ym
         CmIY5KmmY/jzk8pQ/W0tB2xMcbgttY262DzXELgfedTdEkwsmdmVQ6j9UcCixGYDHt3F
         vjDKDuR9ZSwiKKSeWTAELASuAeanDNlsyh/d7ra17nO4N2vV3hR+gndcXTd6SGm69ukj
         MTL/CuOUBsKKjS0E0/EukL8KQxArMVLT7V0wD3rZxk4wVZf/RtNDFU9nJMCJPzqlDArT
         pCCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Y2N++5Dt13pDZEAAvSk476sZ3cIJUnRaLaFTqWo52BU=;
        b=c3xFxzw+GhfQYak5aspMPU8B2o6lpf8hrDmjZmIergPcQBw/wOsXolYzX2i7SmAQWM
         VtuoFduWQT1EYqdHFSHMiY+CWSxjItKnDTiolXeHRo/dvLobFdnBHDEip1zzn7R8Igd7
         nfyHaQJCETbuuywjIfldQXMhbDXxzNcoVActqTZhxeL8sk1k+NdqXMTWzeBBxbzS7g78
         qfR5xDXAtuewKRiTgatVMidE+aWrSbkV7nOCM6sJnUOZqsxj/ehiJ5hG09gs91h+oF4b
         jtaMm6AW1BRMqx9ILm8U3jhmDuXGRuYjti5+ufYWM2VOyeliFHzkg/bd9YsSqOL8EVTj
         Pi5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fqscOD+W;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y2N++5Dt13pDZEAAvSk476sZ3cIJUnRaLaFTqWo52BU=;
        b=dMVHZxFC0XhrstNVl3qmNl4yBPCw3KFeG80X9K4PttftfQdxLOYXW05qQuhsAfTDEb
         Bag+i6Fzu5mfJumeVVTzG8d6HuFPAGEQjpTeDag520I4UsPL1GXP67EmRLL+yl0BiB4S
         15sv6ZZD/X/Zz6MUbdElkEHAIPRhDmra4MfDq6zk2asNJQbhxo+PJqjPh6qGQnpqmM1V
         JlDpjm/VJ5PDL4hq0efatBuc8eDwcCrguf9dR3OoNyvVoFZc7Ey8WG/eYhkpD9wF16Ma
         9U1wyj6x5EA30tRcHMa5e0k7HUIcc+wxBPKK0XXSLirpvmYXklBjD7WRC3pM+ySJ4mje
         E4bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y2N++5Dt13pDZEAAvSk476sZ3cIJUnRaLaFTqWo52BU=;
        b=tv7qZ1zswcTKDe4TiljI1aoKnji4YLT0JtTVzGWMwSFXPI6MlWaNmVsI2r/7KpjNk3
         TiMnUeS4MGEooA3biqWSvbMFdlHrsngpiXMY7iQsjlIfefeHXoXhuY26hFo2bDvVqHJ/
         TihNfq5IX2vpH/0qNeP8MxQM9Ogosg9tp5ITiEj6C54VceiGP8r4zOrC9wP1mp3gZrf9
         YLSXdm5OdzTm71pKAeqnhVMopmcvX7Sj5yDF7ktEXSGvXQl5Tsbi9GhNBkntIbhvIbe7
         QLrKNQb580EjQ0MjEUfkcZ/aodBXXqCAbN64NUKFD03XMQZ/bPmWIyrT21B/zdLMng6K
         pZeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VkggTlWrVY2Rn+IU3texTmXqvhUQTad9nPMq17KSq5BKR2eL+
	FRHY2l1cPkjr9UxfMjKWY7Q=
X-Google-Smtp-Source: ABdhPJwB+gadXBkqxHtv7xEY7ieXvnbWbFhmjoSm8MJWxoklz4vH7aZhiCR+VyzQ7O78bVW1Z0WhWQ==
X-Received: by 2002:adf:9d4b:: with SMTP id o11mr13363486wre.29.1630344398040;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b84:: with SMTP id o4ls1795885wra.0.gmail; Mon, 30 Aug
 2021 10:26:37 -0700 (PDT)
X-Received: by 2002:a5d:504f:: with SMTP id h15mr26712139wrt.69.1630344397167;
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344397; cv=none;
        d=google.com; s=arc-20160816;
        b=C27EOJ3E3LYcOKY7oI78F+X1e3YvwH8X3cM/DACTwFSvdSCEejYgO9RAv1gqoAA40E
         YIURHidT6H/MuyoToMB4l/n0TqH/pSQzu3qeQrdKGufA7Ns44ke5FQlYdse7bLeogikN
         3EGrIWZGKoNAo5h3Lfpn1sYsJ4Y9B1zVtzCWFsFY3hg0HHQDj0aiGrBBsPephWAEcNg/
         TTfHiwFAjJ/HIuve15D1bIWjWekxy5dzYjxz23ucjLNEBUz7TaCsiNFdvsG4CcSAuGeL
         W7xppVMu22qHbBUabyPxiyV8yBXpVgcMm3cXPtofSsxRuGrN0wt3XDJhDPb7MIvtLny9
         9XZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:dkim-signature:dkim-signature:from;
        bh=/TlNdEaYuWrznUySCkzWevBs6NrmuDYVGSJKO0VUco0=;
        b=r+pyJo7GMnU4nzmSosqn14Dvo60ya63v7voxre9CKnGB51YD5F6PCczyqCvNDCRXEZ
         3xyAVCJCpECat7PolJwCkz+3lAHm0pU5PL1EP/CzBI/SN/DowtoLQmyXnjnFgrbpyN9a
         7LHT3X0W9nFeDO/YUmWJqFaiVY2qQJObG+CP1/1rX6gbKETf8VihpMHbwDnPuEJdCQ9l
         87vho+BVcHiFkNMjnmttw2TKSmy2gdR22GNj2WRljXbzpdT0O6lYXGmyHITDnPWu5iAP
         iwT7UmB59YLvJiBJ9P8EsR0qD2J+bfcbroZ+M7dp2q0Yasc4XMYmFgDpNy0m7W4erd5v
         dvXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=fqscOD+W;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id q137si7481wme.1.2021.08.30.10.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>
Subject: [PATCH 0/5] kcov: PREEMPT_RT fixup + misc
Date: Mon, 30 Aug 2021 19:26:22 +0200
Message-Id: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=fqscOD+W;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

The last patch in series is follow-up to address the PREEMPT_RT issue
within in kcov reported by Clark [0].
Patches 1-3 are smaller things that I noticed while staring at it.
Patch 4 is small change which makes replacement in #5 simpler / more
obvious.
I tested this with the three examples in the documentation folder and I
didn't notice higher latency with kcov enabled. Debug or not, I don't
see a reason to make the lock a raw_spin_lock_t annd it would complicate
memory allocation as mentioned in #5.

One thing I noticed and have no idea if this is right or not:
The code seems to mix long and uint64_t for the reported instruction
pointer / position in the buffer. For instance
__sanitizer_cov_trace_pc() refers to a 64bit pointer (in the comment)
while the area pointer itself is (long *). The problematic part is that
a 32bit application on a 64bit pointer will expect a four byte pointer
while kernel uses an eight byte pointer.

[0] https://lkml.kernel.org/r/20210809155909.333073de@theseus.lan

Sebastian


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-1-bigeasy%40linutronix.de.
