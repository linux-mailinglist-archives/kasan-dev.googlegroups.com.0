Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX7GSXFAMGQEHKCVCYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 28D71CD0980
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:41 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-599cdb859c9sf1590538e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159200; cv=pass;
        d=google.com; s=arc-20240605;
        b=E4yTILjb8w4r0gvIVcCN2SRqz1t+s/R08YXFkeACNwx636pwPBswqYdsz4HoRu1yDO
         AxtvZMwegKVg5QOH4MgEW/cpjDmx16QR7igmZyvhNu73O+dvEVhYuKfGG6z65zS5Fd53
         popvdNCOWrPR4L1A3FcPaGmi13h4vPdZHOXJA1VPjriG8/nf38AXrkxgOzSQS8Va61Lu
         AWDVc/TGXdmtAEPfgcUGB0mZVLYKaXmtdZgu/Mirq/nWvBeNJ+LolTJJU+rRmw69KCu7
         ya7bY430qRsphp96qLOWBwFJUOgPy9tzkHPpg4MWx6kB2VILfY2BfFP46JNZ/6J+ydtZ
         SQ9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tE75FC7NhSjjIWzJCUjCMgZQT3dRv4/m2cVJUDLPYNM=;
        fh=/O6jwm1kAwSCJwjMbMaG41OaszSYsqFlmhACYFOqqjg=;
        b=TTior0bx3/CfOIWr8gwh9mUKjUDazk42MQg/a4dJhC3CpblUQW8AZFsT8lTkDKm46m
         4bQXQjcx125jxAqBTe91AF3w1D3+GLiNcXSE+jvfH3w0xn2RcOaBaDFO2FvYxTsswqlu
         S3Ut5eFHKKL9WnvX6kTHtL8Kgir7kvjFs5AUojaFsRE10NEAvgL2PXamu1jR4h+u+YUP
         dRzTD49qBu+AHibSi4gp8n+XhcPvIZTsSnrZmzcU9VhE2RW+sOSYhwYk1az2lr9oHtA6
         XvmlavIevK7w6JhPMwUo2EzKJgoxTf1mm4codZ1h19dOKXpYGbX5W7MYv7jtg6Dzyhrv
         ngwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="EG5O5d/+";
       spf=pass (google.com: domain of 3xhnfaqukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XHNFaQUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159200; x=1766764000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tE75FC7NhSjjIWzJCUjCMgZQT3dRv4/m2cVJUDLPYNM=;
        b=dpihCGdJJ01PmUtbAjHhhvz3Ep6JDJfs60d+l4+0SwxQyYB+K6InQXv7Dx/M7cUKcY
         M3mEpn8xMMKHBDOUHiZLG2gSG84YKnxizXp7bATZvIXRNqr1047mgQmJioZRlHzowXDy
         FpnCCbdwj6Lt/BPJKe2/pWOOgNGZxcja42dP1ThHbO56paxn4J29XhaAc/rFkO9kiGGN
         z6MQqkajsznWmUAYlS4gRZI8ypR/TtB2LZ3SvBahU67oVRteeemHY1X9XJHdM0DxYzDO
         smRbbYZ8gmlqtXbgn/hSDL75eTJ3qdLvA0FkIsSFCFCwLcwBsikMvZn4vsgNDCyG/7Cd
         nt8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159200; x=1766764000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=tE75FC7NhSjjIWzJCUjCMgZQT3dRv4/m2cVJUDLPYNM=;
        b=BWybjYpuZ4CrM3RbobwFMuNwU0UOkSVFBV0AeFJK2oX724tuy6vaKJe5fb1Z+nCZxB
         7q+bS7WVihlnIMD39RSxPUNFEyQqFV2up1psgWn3xuJcBlNlOvw/MmzcJzcMS2ZkXneD
         120SV2babkqxOYDuio0Gk5f/S90oZmjd3XS7S1dJ5F4QcY2OLg9oV1IMcB4BICxEmJtr
         GiSghPfilHE0M5b200u7z3Ldyf+xZvQ/Wa8lI4zODVEbYGpjNENhRvx2rLQdHWwkPTc4
         Mn5tDTdBTDmlVIXPulrk1HF9oZwCm/StuqXic0YZLZad5zvZWkeV8Z09+c1X1oD3CfsT
         c6hA==
X-Forwarded-Encrypted: i=2; AJvYcCWjbuT2kQWH5ZOQlpwb2pBBFw1/KgUK2Ug+pduqx2/laoz947p+oiAGdIXC/HD/S2EOY+xghQ==@lfdr.de
X-Gm-Message-State: AOJu0YwL6hnyr8q2BVc94qjwsCh1OoUJTqFMFdLDvW9eLF/kFhQz4qz2
	EM+zwfmsTeL+GiG86vY7Ozh3SLOQ0ugDXsjraJ+kltN6KARLpuny+hrx
X-Google-Smtp-Source: AGHT+IE2NZrvz/F3VkOyrspf056b76WTEu/TnZuggeXozchryaT2gWp21hOI1a6etD8g81+fnBjRyw==
X-Received: by 2002:a05:6512:3ca6:b0:59a:1240:dee1 with SMTP id 2adb3069b0e04-59a17dea37emr1176326e87.40.1766159200313;
        Fri, 19 Dec 2025 07:46:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ2xW8vbxEdZfxmWUEBGVSXho3Vi6VVDwKxDFVHEZdwCg=="
Received: by 2002:a05:6512:131a:b0:597:d6d8:7e76 with SMTP id
 2adb3069b0e04-598fa385bfcls2568908e87.0.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:46:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX1c/X2MBEdhGy9x1tVT/k1kAnFx/Z4bJ3CX5GANWuBLPMTR/IyAG+taxnZgkFgSeu5l24iyQXh8fE=@googlegroups.com
X-Received: by 2002:a05:6512:3ca6:b0:59a:1240:dee1 with SMTP id 2adb3069b0e04-59a17dea37emr1176279e87.40.1766159197453;
        Fri, 19 Dec 2025 07:46:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159197; cv=none;
        d=google.com; s=arc-20240605;
        b=fvY5C8tnU+iOdHPjBEwSnJpnl8y6zJS+C9xQxKBS/K02OA76xI3CQW5GlLu1Z46/qc
         n4KUQ6KtqErDm/t834m8BCf+g6YeynYSDn7Wi7NYO7ORclvjECxmTBNQJDc/5/wPyzQ8
         qsTL7V4nVOS1wSAuYWq2vx8NYt5IANLAe74ACA3xGYg1yK9SwYnGDgcaQFibOeiVluSp
         PclUx3+meptKLXE4meb49C7COS5823wpGVbSM6Qail7FqBl/7C6UN/QBZC3HbTeAhLy4
         bX61hb2/8xQvdjbUOJrsal9HH4KG0RaC735VTBtKlEKz4LztrnWkHOFwQqWH24E6t6pu
         C7xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=pnCWdNxOjiV83xbv6/Q1ySENLnYMSFtAYAkCgCH7C/E=;
        fh=jIKo35zpjMJigmkhXdo7ui0szsOAQRqzGpA3s0Hwfm0=;
        b=T8M+ZCKJ7zqN6yWP3QUXdRisyIf2ISCKRa3hC2ZPy34RmNWOiZVTNNVWO2FGIZ9Eu2
         CtPgGgVfp1uo6awh2mi//8aMc6ovl55RQItU9LEJ9aiRCWWpGFnCWAwPYeXE56KvL7TL
         GPzmmK5sbIR//O72Bjue379G9UJzfyjE/aaZpA6wSaZPor/Si6nMycUwzD5iGj/xck/X
         avR8deSnob7/b0HWfrs3mj5eU2Rz2392gPLZEr0PNb/MZAhFeVzqZq6DfgnTJE2CISAy
         pxne5IEAWdEdwfXEK9mdULyRINhwn3iiqWL7LdXtV1Eop+Phr8AgPnceo9QVOChSY3d3
         WLow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="EG5O5d/+";
       spf=pass (google.com: domain of 3xhnfaqukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XHNFaQUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a181bf532si63247e87.0.2025.12.19.07.46.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xhnfaqukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4779d8fd4ecso12101585e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU2vk9MaBrr0+p3v4s1wQZK7opc7lbm3iQayeCcB1GSEiVJedFMCdnJYd1+VsGbpoNpXDq/qEIjTf0=@googlegroups.com
X-Received: from wmcn13.prod.google.com ([2002:a05:600c:c0cd:b0:477:a6e8:797a])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:888b:b0:477:9cec:c83e
 with SMTP id 5b1f17b1804b1-47be2999667mr56775795e9.1.1766159196727; Fri, 19
 Dec 2025 07:46:36 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:07 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-19-elver@google.com>
Subject: [PATCH v5 18/36] locking/local_lock: Include missing headers
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="EG5O5d/+";       spf=pass
 (google.com: domain of 3xhnfaqukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3XHNFaQUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

Including <linux/local_lock.h> into an empty TU will result in the
compiler complaining:

./include/linux/local_lock.h: In function =E2=80=98class_local_lock_irqsave=
_constructor=E2=80=99:
./include/linux/local_lock_internal.h:95:17: error: implicit declaration of=
 function =E2=80=98local_irq_save=E2=80=99; <...>
   95 |                 local_irq_save(flags);                          \
      |                 ^~~~~~~~~~~~~~

As well as (some architectures only, such as 'sh'):

./include/linux/local_lock_internal.h: In function =E2=80=98local_lock_acqu=
ire=E2=80=99:
./include/linux/local_lock_internal.h:33:20: error: =E2=80=98current=E2=80=
=99 undeclared (first use in this function)
   33 |         l->owner =3D current;

Include missing headers to allow including local_lock.h where the
required headers are not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/local_lock_internal.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock=
_internal.h
index 8f82b4eb542f..1a1ea1232add 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -4,7 +4,9 @@
 #endif
=20
 #include <linux/percpu-defs.h>
+#include <linux/irqflags.h>
 #include <linux/lockdep.h>
+#include <asm/current.h>
=20
 #ifndef CONFIG_PREEMPT_RT
=20
--=20
2.52.0.322.g1dd061c0dc-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251219154418.3592607-19-elver%40google.com.
