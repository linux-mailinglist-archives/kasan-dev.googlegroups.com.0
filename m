Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIHA7TEAMGQEUBZQBKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id F2423C74C8D
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:37 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-37a39ed76c8sf8462221fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651617; cv=pass;
        d=google.com; s=arc-20240605;
        b=JEpTN6SrHHjvf4Uhk81kbRqsn06R31ryRXBInwaBXLgqNw+cYZYH7T4iR1yjgfiO52
         gqJtgPX++Mpt8y5S6bAQy6T0hrZrTT0avBo8LZJxZ+fdGHzz26EgMMjMxMqoVwYfUCO+
         T7KmpsS0ZlnO8p6tUDMvWpZM4q8XeobeoA0Ai/zuJ3wxD9JE5k2zR8PHbf9R2A8IwuMq
         ATz2qRxzOghgjRE1HUlbh+h0yY5d9R5NWHVSLiIYF/HLYRqLNZcAg9o0Po0CRpl2w1s9
         wUU+//pI59+D8avoVVOEukXYV0jTvmc6Uk3+mn/wrx6uZ+sO4PjnvWyhmTxFdHCHimnN
         TGEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=G6XHMmES+ossm/V54mFG3jX9c7GT0rev/l8u2JSW8+M=;
        fh=URsw30mV7ntShGTcdkBa5qq9G76+VEipFJybx/2nJcE=;
        b=JIQ/Qo4gdu2US7OKosse0u5e1WSZ8bbBobaU82pjZOUByUNo6isLG6O40ZR+w3QKbV
         Eegu2/bcr10gzwFK2ZOa6FMzSDUQZg/OTfHOQhorP02UMP76pqbT2CzvkUpf5GUbefFp
         HfUItdaAIGjD3GRV58wE5NqCnO8KrvXgeCvKh7Kk2CWFzvCTtn4zZag6GX1Mat0CbcSD
         IbCZlNuAIglEqvwXPpe0lGQK8RQp1wXBPL5v6XSjLX3F/rlU3JtkoZyUFzRT7XiuTKDE
         gH6W31ZQySy02KnMcRDODFDlAvbBeoZwpYQYuVVs83Cxckp2XEcHJS84YjQULbDHJxZW
         APQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sGjpgOpC;
       spf=pass (google.com: domain of 3hdafaqukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HDAfaQUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651617; x=1764256417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G6XHMmES+ossm/V54mFG3jX9c7GT0rev/l8u2JSW8+M=;
        b=URQdy9IIFmxhQXzpQvVobPb8u0ySyO9G9AyYLa/J4vLVPHDUXsA3q++o/1Qza89pVx
         Pui2+AmOlLDDJnKDiC74DFkGwylSc2g7XJkCohWEGLGUdI9UaCX66CDAcD4+NtsFRb97
         Jeb7EBHecxUDwa3q8GXKxPq3RuA4zduXVPWNvJC2u6FgLSpQHJw1Vre3RJo+tgpofdte
         aBBi58HExcS+u7KCNatppfczdS/so8kF5HANNfYOWFT+rHG/6xnBv0uSHIPFWgD8QbaC
         Tt6Ye/GnTJJNBGyyE/DhR6afOTen32pP0lIy1WI4fdg6cdgbflClxJ/O1gXRjZgGArIN
         1yTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651617; x=1764256417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G6XHMmES+ossm/V54mFG3jX9c7GT0rev/l8u2JSW8+M=;
        b=lZqWNGJxjMXTNQB3d/Yprotx7RA+Su30tmXSU8oFJMcpJofdhoTHoq+GrE/Mqpzo/Z
         J3nhSCuTEjZlDyz2bK3ZDWRJneuk28Mh+AJzMavD8eMlY35yB91VWd4Vp5Pqagyx5910
         Rz7YrmC1ELYTm9L1Y4ZCeGJqFNDDByhq2/Ycwt9tn9MDWT3hpt8JQkPvcMuTxsLI4RYH
         eqqsTUWb2UNn5fX7qy7V70abWJBYbgmxVOFqEdb7EegdXnmjPwkaOclfcel2+Ws42+Y2
         R42jFLpdKsujn9HYRM6Wq5tPSwIDiw3KxYfSHvk5avmycOujvGJ0s4HOhxTIp5TNcLlT
         pxJQ==
X-Forwarded-Encrypted: i=2; AJvYcCUxeNkHLnXlQYQiMVuMVMY6DLmqxkOooZ8/UXaUsbswtX5n98kTCa4RXNMP90y/8HbGyhcCzw==@lfdr.de
X-Gm-Message-State: AOJu0YygIQlVh/F6K5g3oS1GyTWlVhP7W5lHZ3jA2//n8U8JSZ1akNUS
	qh1Mkr1rdh8RWUlXFHg4vGUt6gd88yzZH8kW6CPL89XAHuFU7mvUZIrq
X-Google-Smtp-Source: AGHT+IGizw+bsyp6BjNPVQKr6iIiX/aodTlKNyZFstAdGUX0q/nLMHeehB5IrRuvSN5g282BNDGdGA==
X-Received: by 2002:a2e:7219:0:b0:37a:2d8c:c0a8 with SMTP id 38308e7fff4ca-37cc67b51edmr7795441fa.34.1763651616983;
        Thu, 20 Nov 2025 07:13:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aHdlf3VDabUL6cPuZFEY6P6A0XFemHsR/8WuBM3u37Pw=="
Received: by 2002:a2e:88cf:0:b0:37b:97ac:627b with SMTP id 38308e7fff4ca-37cc69f16e7ls2778361fa.2.-pod-prod-06-eu;
 Thu, 20 Nov 2025 07:13:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVXkravydVVP7TDCE8Bq/d74Rrg1VY+wTWdFISOQbqaI28udhaRWbt+W49wwH2coufZrK/sNuxsftQ=@googlegroups.com
X-Received: by 2002:a05:651c:4008:b0:37a:2d7c:3ce3 with SMTP id 38308e7fff4ca-37cc676f635mr7261511fa.14.1763651613631;
        Thu, 20 Nov 2025 07:13:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651613; cv=none;
        d=google.com; s=arc-20240605;
        b=SoIP2E7E9yV+aJidXTpMP2/s0N7q125QyRHAf47CU6PJxMT6hUv4MKtF1ieNiLv5Ud
         Ti9/p3j8MWXDzFsrhtF8Irab24r5LvR1P1rcBJ3E3ALox88VEGOl7L8BYNnrOrigM3k6
         LMInNJEivZEHeinklhxg4+5x5q9NQOXpI+7Fjqwt7CZIbGM0XzS1zvKsoOzgbslOYVeH
         LUyk6ViLTFJi4+LRAO2lpHK96SOm0/g/K3OWIUI3pwFN2PyOSBv4o0DiZOKZUe/rcXcT
         0HAf//vf6s/11Jc0B1jTSNLmyBMJ/2vaUMRCmiXaHqR8Fqk7VREax4QH0NK7dUyf/sIK
         eXow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xNvl5AadBnBbkNqIZ5ePr/ep+DGb1qTLi02EcnmaTpQ=;
        fh=yKg6dBvbmnYeXiiMy1wLNlNK49riiUjF+68c21FH2vc=;
        b=gB+tSi+JwXnOruJx+78OCY+jTF1Xb6hC1huL60wYeTMGOePXUjpmPpwOR9A7ZQfUhW
         c4k4C3RNtpFkhiOT4iMksWRdRTE1qQLuBccMxvbW9EMlujPBTlAcHJmOdNYy7zHakOEL
         XiwqSDjmdnvDrvyyTsN/h+Nf7cQfgROVZZX9QIDXsDtRJHiMbEq1a0EJHJn6xHutVkHs
         IiU/xpdF/0Fzua/ByH1Yvf6g6s+76DJCUvab+8qqLpT5fNfHOwG788MTUg4MeuFgR5zk
         77daEE8AYJA9vpOkh8eON8oLts6rocANH0y/hQgHcKkMX8Ylc9czGzdXR7BdKExLTV0X
         L3Dg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sGjpgOpC;
       spf=pass (google.com: domain of 3hdafaqukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HDAfaQUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6ba523fsi448091fa.8.2025.11.20.07.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hdafaqukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4776b0ada3dso14302705e9.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVHf000HNYagNBysa4mtRznD4bJsnEf2mIKCZjnXZbzQpa7JjAIo0frpc3VtxENGMK++qXGy+LIcGU=@googlegroups.com
X-Received: from wmbbd8.prod.google.com ([2002:a05:600c:1f08:b0:470:fd92:351d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1516:b0:477:14ba:28da
 with SMTP id 5b1f17b1804b1-477b9ea8f78mr18741385e9.5.1763651612613; Thu, 20
 Nov 2025 07:13:32 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:51 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-27-elver@google.com>
Subject: [PATCH v4 26/35] MAINTAINERS: Add entry for Context Analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sGjpgOpC;       spf=pass
 (google.com: domain of 3hdafaqukcukpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HDAfaQUKCUkpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add entry for all new files added for Clang's context analysis.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Bart Van Assche <bvanassche@acm.org>
---
v4:
* Rename capability -> context analysis.
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index e64b94e6b5a9..0445478f74c7 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -6029,6 +6029,17 @@ M:	Nelson Escobar <neescoba@cisco.com>
 S:	Supported
 F:	drivers/infiniband/hw/usnic/
 
+CLANG CONTEXT ANALYSIS
+M:	Marco Elver <elver@google.com>
+R:	Bart Van Assche <bvanassche@acm.org>
+L:	llvm@lists.linux.dev
+S:	Maintained
+F:	Documentation/dev-tools/context-analysis.rst
+F:	include/linux/compiler-context-analysis.h
+F:	lib/test_context-analysis.c
+F:	scripts/Makefile.context-analysis
+F:	scripts/context-analysis-suppression.txt
+
 CLANG CONTROL FLOW INTEGRITY SUPPORT
 M:	Sami Tolvanen <samitolvanen@google.com>
 M:	Kees Cook <kees@kernel.org>
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-27-elver%40google.com.
