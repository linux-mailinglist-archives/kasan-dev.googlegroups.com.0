Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJW37TEAMGQEUREZLUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B5132C74BA5
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:03:03 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4777b03b90fsf6110945e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:03:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763650983; cv=pass;
        d=google.com; s=arc-20240605;
        b=CrUwYQl++itFWD34FbCnRQZLKx2/zaGSD7nWrup4/5Ve5H5ljxH4WBKj+u7iCTIEE7
         MwEyCOcDwVH1dHo2iW3vQMc0TWd3W79EC8QSmMU6g6o4iCs5LOAqpIJiOD5B9FDToZLb
         +E5opJv6DjzAVfAOsvPDkjfj/IVEiCtLBtsMc93aYtwh5c8urElFLoqYimR9NnUMR1It
         fvErn1vgAgXirwAByS3Y83nErpjZPTyb960TxoDQwkO5BKS4psizZq7Ru4TgSFxeeO/q
         0QdMQGpH0lpNN8jb/ysqDUVkGSXZo2iuKCkUmvevsh1rHuxihvm90qyu6HDzZsYCMayF
         y16w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zCHr/5z65pY0KbfDxLFrip4BVjxKV2UQeo+pFNTT/Is=;
        fh=psCMmchqwE0+tJw0LG4P/SLsL9biu7R4aKcaKsJHl4I=;
        b=OBm5R0VjpZzV3JIZcxzS17Zoq/WCQ2d+7mw7/KX44P8eVAlsliKRJ0ANDVb7nTXpPM
         GM8Ctzq6yStnAX0EVf6bhWLILn5QbovFNRM+Ytfy2OcCxQieP1N2u4N7I6lc2jC4zXt8
         xFANyurilP5DfOFkoMiWlgYM0mfVdobMjqntKHcnHG1W7W4cEf/rMTrbCyiaDa2wFYzS
         D2ZLigm70mRePHgmOOZ9w1qZJQrA8L2k2SeZWrmZ3nboE/xzxypNEWDMnQ/xiDMTQH6F
         7+aG/s3F5zX32MjbyyaZ2cRGp1uBoSoxG5nkvLkPWDiPCTIOZjevk4gVq7C0npnyIRtO
         ud8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0UiotrxV;
       spf=pass (google.com: domain of 3oi0faqukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oi0faQUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763650983; x=1764255783; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zCHr/5z65pY0KbfDxLFrip4BVjxKV2UQeo+pFNTT/Is=;
        b=E5FadSfJ0+OG23xTHFSOJg6NEwSJtebFcuoE5iuDFle8+9gp2i6QToErp5VSxxHxP0
         0dmEpiKgKJ9Ci7pAvl+2e8VB0v0wRCwJ2a6SKMD63LhWcKfxXLLAkHIteYj8/DiY4S0Y
         Lmyfk/rECJAaPodjv+KqglySkD+i/IRhm/olZqODiYhn+WY1MxY/qWG2UbT8Q/+9Yl7L
         hCBzARpqxA4NcWzOqDBUJFKW8EKKdSLga7wi9bnyqolfCGhXxuBuODkGcPM3w8LaksY4
         m7WJZFwOfQrRxapYjvz/2nWRU9RIg7dS0RXpNtO4wX+UQTzAHqGxN88M6lDj/kvLS/Hj
         wLeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763650983; x=1764255783;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zCHr/5z65pY0KbfDxLFrip4BVjxKV2UQeo+pFNTT/Is=;
        b=vYYJ81u6msHZS7RIjWtE3Sj9K6Ag/eskFzKbZkG7QJ+KMpfBBn5qzbXtAX5Jg6+NZz
         j8zDzpYAi+EX/W/K4tPIGc2Ng9WCmSglZo/pWCGF/yI2nPgqRFNXSn6xVHDX8Eg3TB+p
         aI4neTWMhjfYSkGvI1/89/r7upPiaISsJEwq2p5eu/6F1VlAIKhRsz45OXELYOx2sZ6u
         WktyM3yMdpKVCnPo7sjqRMr8fqFgN+shFiJTpihZm1Kr4uB9qSgy6AVZIhZTDdvpLxwm
         6MJ9j08p3YYIu9EOD9A0a48bQYIDH4dB4Pro303ow2/NC0R4v5DfWjjsVrOtoDobiKD/
         fzyQ==
X-Forwarded-Encrypted: i=2; AJvYcCUFOwoIw9FbPJ4PjW3lcEdtlQcjA3oXmcVeW71fI1PivBOut8oHG2EB2TUmadtN7GCiQ391LQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyzb/jyHOcdhF2oAEKE0l2k5HmmGRYIFhbahTP5djmrLGxPcv59
	wY7iBIVsSZVyV1MEfHFcdKEwW2yfmIdKI4Zro20lNsN8il9cFUXeX4ee
X-Google-Smtp-Source: AGHT+IGsmBXfuG4vzo+hMyQ1ztt9EIzH1ilpIW3L4zgBQII7wKWTSaqIOJk8oumMhzwGTjL14ApArg==
X-Received: by 2002:a05:600c:474c:b0:471:14af:c715 with SMTP id 5b1f17b1804b1-477b9dde154mr26610115e9.3.1763650983048;
        Thu, 20 Nov 2025 07:03:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bb+QeQlpN/Dfj3kIiLvmtMUnrpxKYM5oQ7wEFPcxxTnQ=="
Received: by 2002:a05:6000:2903:b0:429:d66b:509e with SMTP id
 ffacd0b85a97d-42cb8220d95ls560460f8f.1.-pod-prod-03-eu; Thu, 20 Nov 2025
 07:03:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWsefvkM6vYzHgjO3w2Kxwx4VZ4/q4f3KQp3RlseOHEPH84xEAgcd7vwm36TASACtUpRBMulZp7qe4=@googlegroups.com
X-Received: by 2002:a05:6000:1789:b0:429:d725:410c with SMTP id ffacd0b85a97d-42cb9a6474dmr3368014f8f.44.1763650980011;
        Thu, 20 Nov 2025 07:03:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763650979; cv=none;
        d=google.com; s=arc-20240605;
        b=CpEmBzyXxCsleEgVetl/EaV6dyZuBtU3t7BiGfsBKSEjdpRHTgsdvZPXEEQSOxWteC
         FQpSW6hM4RzVFXVMN6iwKolZUi4IWs3x6Mv35DRrZgnjG3hgPr7MJou2XDDyxLoCGzXr
         /x/jtL91yAn917F4m6YUNRjjbt5cT2bw0ibn+XeZQVYvkFYysqYa5VCDZk5hau+FBs5+
         a1p1LaBrTUSnqYajnvsKKtlmqe6r8DtEam8HyDCcdo6DIoBI5eJGD0oB20UjExSlfZUC
         2IC1j0QLzXEd+oxteiEdjtvgbSgquE/AwYkf7rDNn6XzII++ea9S6Pfblrlf0V3nApPc
         Jc3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QTNBohfvQLfYyJiWHtGyLx9FZqAAISthRH9eXaAWBIw=;
        fh=FtiMgK5Wb2GU2iF31as9t7r/DyE2okKFGPAZynd2YF8=;
        b=V3pkMmp8ZeHfMMklN+pdO29Qhfh/J4m3N5s+KXrFzfLW3IVAzaZC0jCi9nxPhlsmDi
         KVrYttAqu9YiPPtVFttegpWKfBQT2CkSo0WgDR+vZxVhUwe4Z3TggMUZhIf4ICmqvX2z
         ZHqZqvV2vAO9ZdKGUTsTfU7R8+rbraSE3wdN3pG/mQlCXvOu/tMrmOuA8QxUXK4Jh3YD
         JTf7QTTPGQP/r4owEp+bhoygSojzexUfg0YHVD1Z1VTNzG3nZfH+P2AeS5OJKr61qWwh
         4ZBObR29S7VjCvAt23feDV3Ze2Yy1AwAyeCvzBgzh0RxTFtSDO/m4n3NKE8G4EScsD09
         OjFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0UiotrxV;
       spf=pass (google.com: domain of 3oi0faqukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oi0faQUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42cb7fa3583si52358f8f.8.2025.11.20.07.02.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:02:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3oi0faqukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64165abd7ffso1295533a12.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:02:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/eMBmMItYzcIpJosV27NniGeJY8SKKzxFc90jiq+yH9K8RUYEdv81zt4wXfLiWsEiwsyDIxxiMPI=@googlegroups.com
X-Received: from edb10.prod.google.com ([2002:a05:6402:238a:b0:643:5f58:caa7])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:268d:b0:640:b1cf:f800
 with SMTP id 4fb4d7f45d1cf-6453d084770mr1885049a12.4.1763650978915; Thu, 20
 Nov 2025 07:02:58 -0800 (PST)
Date: Thu, 20 Nov 2025 15:49:07 +0100
In-Reply-To: <20251120145835.3833031-2-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120145835.3833031-7-elver@google.com>
Subject: [PATCH v4 05/35] checkpatch: Warn about context_unsafe() without comment
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
 header.i=@google.com header.s=20230601 header.b=0UiotrxV;       spf=pass
 (google.com: domain of 3oi0faqukcckt0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3oi0faQUKCckt0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Warn about applications of context_unsafe() without a comment, to
encourage documenting the reasoning behind why it was deemed safe.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
* Avoid nested if.
---
 scripts/checkpatch.pl | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index 92669904eecc..a5db6b583b88 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -6722,6 +6722,13 @@ sub process {
 			}
 		}
 
+# check for context_unsafe without a comment.
+		if ($line =~ /\bcontext_unsafe\b/ &&
+		    !ctx_has_comment($first_line, $linenr)) {
+			WARN("CONTEXT_UNSAFE",
+			     "context_unsafe without comment\n" . $herecurr);
+		}
+
 # check of hardware specific defines
 		if ($line =~ m@^.\s*\#\s*if.*\b(__i386__|__powerpc64__|__sun__|__s390x__)\b@ && $realfile !~ m@include/asm-@) {
 			CHK("ARCH_DEFINES",
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120145835.3833031-7-elver%40google.com.
