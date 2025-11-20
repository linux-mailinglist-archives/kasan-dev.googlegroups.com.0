Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWW77TEAMGQE5KYXC7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 03366C74C30
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:28 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-59584152ed3sf718975e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651547; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vtem8mlj2PaSoj7hVeNzvz4PIRKuTYRPEL9qkPZPf69iRdvc3ZMWYqLRaAmxibSIvk
         hiY+C+ZaC66nhzvREF4i2EozSkROqadJMtW699bjYQq6TUNCoSah6wcTfOdEINY2QaFq
         92TYhVv4PqwyPMLWO6avBKLVhepkhLONRqTCidoooiKfsDqnza/ni+V6JEo3SRrtUrTP
         5gEUePzMizLThdTKbd0VJeB1og/AD9LPea3792uJsNqLTngSb6pK4My4PM+khP+aISXf
         vhJCAYEnMxgG4W0zRbckeWP639eS52mO13g4xW1O5t+EiwENRocio6sM70auzUWdjgFC
         9nWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=TFt4+THGw0IYjIUBTWJ1eHjvpHgyPfFAHB3aQ14BChc=;
        fh=qnnFfeKg57aH3NUmZpID5WbB8fnKeiYZ52633lYwOjs=;
        b=Xo3WfCb73tct9r4L+xYvgguMcBn3tPN3Wu9VIYauD5f3Y5ABi1GecIHx6U6MaSzQV+
         vyltiILX90mEaT/Gbs0oqsH9/AWd/R6cfxbmgjcIYjd/ntvnPEyFAw1GKM9AqSlVLW6P
         id61lSSJtUVhJgFcq9zeRdRaMrERcUwIwnYerWs2I8VBoPY1rFikVLtz/oSdcpERo2Jf
         noU+/rHSez0AUzFKX08Kz3OGXKGdcYWeTBThUZzV0o43DUU4NerKKquPTgmn1ClOrxNE
         YW6HX/ga/wNvSz89xAfF3F4htNgl/q1teUGk2Dknl1ZVxx0ucfQlUtOfFzLNZlFna9BT
         idJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VQZRHwnV;
       spf=pass (google.com: domain of 31i8faqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31i8faQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651547; x=1764256347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TFt4+THGw0IYjIUBTWJ1eHjvpHgyPfFAHB3aQ14BChc=;
        b=YNfSmDSQM3IVmm+OTYPqd3Jt3TMepJ7+ug69bCEu5EuvIJ7WbbwSHmtrVTUQVKlQBw
         6o3cGNr0+1LFjmaQqgXzTIgsYwXmdR8qSNxYXlAZxXLpN8admiYgTd8bcFQ5KPsTmptH
         fjrhybWF8t8Nb7tP2Fh0TVh6UMPY8xRuN/6J+Q3h3gQXI/s8ZCEkIZrSA+JduqTSIMzQ
         nJZWf1tmJGbWiGpuxPQooyYRiAReHwv3eRy8Z3s0SSW3rizTws1934PbGGFzDQhYRxLO
         taMj0lL89l91A34NhZSs4JYh2D71IFPiGUG+99cNYfHnwqhHWpuRkwPBggXQMG8QTqk3
         CnXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651547; x=1764256347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TFt4+THGw0IYjIUBTWJ1eHjvpHgyPfFAHB3aQ14BChc=;
        b=VoDKaa1AyQ+Hbp27p6Wnd/mY5Y0tCVRQK5SBYkm9upTT/g7WTCRVu7as9Oj3/4ZG5a
         RTxFaOv58Ro60qViKthzMghOeTeob9fl2/2GdXec/HbqRZpoMXnGemfZH3d9/AV7ADBC
         jnXmcZvFSB/vUZeK60a2oBwNlFfHVkLt1MrZer6L3zzd4o64bChcxXSnQZ9e0OG8bQkQ
         jmmpTJB/AFqXfoY9zxgYS4poWiGFXBIp3xQgauGQPRM5wfURkUbzFKzmYTkGE8JfPAgp
         7xj1DJZ6fNlFUQcCSnlaUFIPVH4OYL0vtHw9d4Q7/Dp2xqcpLXAoQhMomYVbbH4idtyD
         b5Pg==
X-Forwarded-Encrypted: i=2; AJvYcCVcvZBzeVClHyh6GQ584y123IbpEymHHn+zbOEZOP1qJtp77hn+Kg+/jKoigcHLcrxNL62wlw==@lfdr.de
X-Gm-Message-State: AOJu0YxxEsch0T5n9M95WKm+1j0RndpqD1n293Bn4bMiclAFNmxkbdEh
	q9SNqYmdVgGnhYUaqYE4MlmwId5yMKxP4IHyHZalAaypo277hvT6xB46
X-Google-Smtp-Source: AGHT+IH1bREHsVvnyNjlkkbjT+B4Pt55eAgdxvFbpOBUtYNZg4pMOPYNhmu2YBZKXe0cq7OHhJFAog==
X-Received: by 2002:a05:6512:33cc:b0:595:9dbc:2ed7 with SMTP id 2adb3069b0e04-5969e320d2emr1234531e87.43.1763651547249;
        Thu, 20 Nov 2025 07:12:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b1Md5j+ntTL5tjYSr81D/zZ3YC/UAqn3U8stOy+Qu7XQ=="
Received: by 2002:a2e:97c3:0:b0:37a:2bed:b406 with SMTP id 38308e7fff4ca-37cc6a7213bls2251701fa.2.-pod-prod-04-eu;
 Thu, 20 Nov 2025 07:12:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZ3/20bU3GGVFZNMyi9l58b9kIn8szJFQszbnpAjEPjZn74CnqQRs0QuGsknMgIArEvwvvl4kFuVM=@googlegroups.com
X-Received: by 2002:a2e:9904:0:b0:37a:2b5d:e855 with SMTP id 38308e7fff4ca-37cc67b0bf0mr10818171fa.40.1763651544020;
        Thu, 20 Nov 2025 07:12:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651544; cv=none;
        d=google.com; s=arc-20240605;
        b=C2VkWPeJRXeY75Et0HPIlYm8UJAAA+TzwMnc9FcE7cNyYUB+khyI/a1hpMrGRTDb2p
         0UudJ/Begx2PpW/WHnZVXxj30sdCp1Nq35HRyFBA+ycFUbYQhwsvBg1Z/tUoTfUNf3BI
         kCsao+1AYZoByEqc1OVAGS7aeCshe0izSAh4kiW1X9eDQ0BgyhAYwnKPy+VcSg2sx6QO
         jzGMe1koJQ0WhfdZ2F26IpLePV08WkfXyC1E1boSxQYXtm7AkWRn22zFVPkt5MwoW+9H
         ax54qGd3tpmRcAoNIuOInPi9Xr6K1cRwNyWY29BOASTtSzXaSk5At9dd06Q6x+YihclK
         dqsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=YhzmKujL7bNVWf02jAjaSOrp3urplpV1YekSTYKrBiM=;
        fh=6QP66+eDvVGmjrFA0fUrQNbEMBgFR71REuNXU461/ec=;
        b=ftAzgbPMkkQm6sRSwKdb+t67ZtzoJshISq96Z1cBJONLoxlflcwbDlhqmDDMBJckWq
         Pi8xEUczdfvpFPl+uZOesiBa/tNDR0vYGgcGHPKKh6IVCo3Cpvs+GlnyjoOA0G5gd5lr
         WjMR672wc7h9ZQYx8iBxGauJYlvTxtfDZwqDG3tLAQJll+qY7WJWSOO2pwEC4GJe02XO
         9sXHWcro4K+G7kTlPu0QbHEk9gYWQA/9GRxqWOoV6slDwLJ5tri0Xfl2D3p/KFrh3ZSg
         v2JiJqg5AwOJxOljAPJgw3urBVkByEMZZCcsIdZBQxT+BCL61fSjFe4yZrOVwdQNoVAk
         aIWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VQZRHwnV;
       spf=pass (google.com: domain of 31i8faqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31i8faQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37cc6b974f0si438501fa.7.2025.11.20.07.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 31i8faqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-429c5f1e9faso1058371f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV7ErqvNvMhgapOFQU3cMpIkGnyYhfPIiTMdfMKlhiIq27uHBUpV53MIElofjYkbJcgwUJKHHYhwsA=@googlegroups.com
X-Received: from wrs17.prod.google.com ([2002:a05:6000:651:b0:42b:328d:1994])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2287:b0:42b:3bd2:b2f8
 with SMTP id ffacd0b85a97d-42cb9a603f4mr3376737f8f.46.1763651542984; Thu, 20
 Nov 2025 07:12:22 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:37 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-13-elver@google.com>
Subject: [PATCH v4 12/35] bit_spinlock: Include missing <asm/processor.h>
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
 header.i=@google.com header.s=20230601 header.b=VQZRHwnV;       spf=pass
 (google.com: domain of 31i8faqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=31i8faQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

Including <linux/bit_spinlock.h> into an empty TU will result in the
compiler complaining:

./include/linux/bit_spinlock.h:34:4: error: call to undeclared function 'cpu_relax'; <...>
   34 |                         cpu_relax();
      |                         ^
1 error generated.

Include <asm/processor.h> to allow including bit_spinlock.h where
<asm/processor.h> is not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/bit_spinlock.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index c0989b5b0407..59e345f74b0e 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -7,6 +7,8 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 
+#include <asm/processor.h>  /* for cpu_relax() */
+
 /*
  *  bit-based spin_lock()
  *
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-13-elver%40google.com.
