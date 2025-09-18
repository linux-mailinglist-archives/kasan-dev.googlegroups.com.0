Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNVDWDDAMGQECTCBZZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05E89B84F6C
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:05:44 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-62b77ca3f64sf843744a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:05:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204343; cv=pass;
        d=google.com; s=arc-20240605;
        b=HJeft09sy7x2YxSO18R0NLtTYa4BngQUM/K+ElPcr69BYONrLlxtTkasqlt7r5ZmTd
         UwuPKgSO9EAAund3C/pk9xV7Hh0MCZIykoN/6blT+Objwtu5s93okp6+2OnD81MGhfo2
         GuCsDlTskLRsA29pUoJ+m5Zq3MSAWoaYUNcnPmwSG98D43bOCVeXpfZCOjr4/x9EfwGS
         XrHwAWS+WO4+LhgCZq+3i5Xru76OPsN/VF0o9ItBXglh5L9kQjqOrksFY5mvRzGqJmvc
         +gOuHr/P7KQOXqc488Z/saZCdOUw7aEWoz1WbzpUXKHsbLrSk5sxBKMDIXA6x3nEM1QR
         tLmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=olu9ZpnHORm1i+29Ak6tAAhMO4eKpO26fB2Ic2PEsWs=;
        fh=AMl21ql5+tb86dC4bA4EcNEyYZ59/tYZvmefzyjrfwY=;
        b=V7I88gShWFQyY0n3lIhtwMiMJCtFOneU4zfwK+/4ierrPUbtvT/KnexEicE5bZkicO
         kyv93N+MU1xmVeOfQMls2QOfgpTYHk2mcnAcPU+Q4r/GxQITjp1l9zzmkGFxl2LGAt2Q
         DTfixt32iL6Y9YEOIqdVuCyQcKOOazqLM+rpeJ7Ci7MDYGsqsNxkv6hM6X2HfS6WaOVp
         RZCN48IOgZeUXMJTPIOEQAtg5nrnVKBI7UVelnqe/atXXpTmrjJAG6OhqRZhT99fo39R
         82S0u919c9rvOmIBhtkSEhoOmGNDBVFSCWpx8lsjkcYL5g9sGQVQmLXq2jWlNV81wumk
         Q3tQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VaKJHSLu;
       spf=pass (google.com: domain of 3sxhmaaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sxHMaAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204343; x=1758809143; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=olu9ZpnHORm1i+29Ak6tAAhMO4eKpO26fB2Ic2PEsWs=;
        b=f33gool8sNPpAQ8E9PRq0q3GfdRUAJZ6LRSX4pIqNdZ/45SiEAicq85W9apurf9Z6e
         vPk8V7c2sf18P/Ktliu2OUr4QQ1nM5xao4nOU9erouYMOKns12uHMMhhsR9VAa6aTnrM
         zL03xQ7W3ZhgwG7Bwx9uURQfafY0piZ17yF9pfpWBaEtLF+g1HnYcy9glG29rU8LM3UH
         ahAEG41+RqM33NobnsWOMDVGsGRClOCL3LN0fSTmvB66e/uJcr+fWttCylEuZng0juP/
         mGNBFFiuLi3bmvRigV5zbuas4FWEr9/DG4l/OljRdj6V4MujVTgCl9axTxb87YrtONBK
         lMcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204343; x=1758809143;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=olu9ZpnHORm1i+29Ak6tAAhMO4eKpO26fB2Ic2PEsWs=;
        b=axPswFbOjMWFC0QSimnD4lqc/9tMgWFXYBLIe6gtFpj9v50JFrncCbwWhGO1PitSlE
         fSzULkKWCN/WoFErlbvDnFc11fd1VyX6hGxITru7NNfVSdP1U2RVBEDxgMaYsFO96AwS
         kcCi+ProdMh4DpsyzDS9OLvauDMbPQn88PEz1i+QdxPhrNivScPOVd/qFxD3ByNzycVP
         kL43wUXmoUMaNYbqbtzZ8A4GA3zkmW6LyfyXOPBdiu9aGizzWv/8JYcf5O2jq02zqVq5
         10yr2S90jV0lX54cTtzY0J3HypqlM7cE0B/jO15mMGwg3ybUseR9s68ZjsspfVBokxWC
         yBrA==
X-Forwarded-Encrypted: i=2; AJvYcCWBL5bLyBsLQHjhkSd1ctNGD/c6Faiwmtz59zsx41rkWbKIAZNUq9PXQvRpF6SJGOGlR9X6NA==@lfdr.de
X-Gm-Message-State: AOJu0YyIahw3tOTGKc4be2UT3CxfdR4zk1RZtbC25IqK98uNKWCUi34G
	G+DdYDcKO9OekbL8G+PaXvpMgYjDHnTfscJJlYfKXK599KvdwPL65Too
X-Google-Smtp-Source: AGHT+IFjwrchRDxwetU27xaqZEwcJu+x5eU6uxE1O/n7NkYawjA4b6yRifrmAJplOaLKVt+fNPHyNQ==
X-Received: by 2002:a05:6402:535b:10b0:62f:a35c:6c3d with SMTP id 4fb4d7f45d1cf-62fa35c6fddmr2710643a12.11.1758204343338;
        Thu, 18 Sep 2025 07:05:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6S/Ba+dz1+JJECDldFJHwUc4nY/FBCBvUTjZmHLJMNKg==
Received: by 2002:a05:6402:3789:b0:62f:4bd0:6c60 with SMTP id
 4fb4d7f45d1cf-62fa77200a7ls652866a12.1.-pod-prod-01-eu; Thu, 18 Sep 2025
 07:05:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfrQipa4ZwgoQNn8KTgcVVojbgwk+IGej523jQBDIQB+meU5qpHnABIBks9A49E1BOu4ymP00FPbg=@googlegroups.com
X-Received: by 2002:a05:6402:13d0:b0:62f:6e4d:7add with SMTP id 4fb4d7f45d1cf-62f83a0cc5amr6360739a12.7.1758204340539;
        Thu, 18 Sep 2025 07:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204340; cv=none;
        d=google.com; s=arc-20240605;
        b=JO31sx4wnk7JoijaZniulYKr18K+D2StlZnmjjb88P0TWtZJM8qjRdo/z/Q3i9R4XU
         iWORbzu/KM+/4qUUYEGoUwVO0RrVmzYb2ydIEj9ACZxL+APqIrbJmK9SE+Qve7okILvp
         JXZp3QOVNIYnvkjJKS8U+spM4spqohBbWgAWFZwxjaOz+8yzgUJq5BxOzgmzpimpcrxt
         7Ccy5PEq8QIc8jqCeXHA2BFz5k4s46gjOjVIzlsK/OueUQNw2MYMGelqQWi24Ri2V4hO
         hOyrk8bsO/k7wflZNx4en8oaK7k74VaWunbpoXpVuVLvDSlsvAu81poiuBybW+ATgs1v
         LxWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PkIaNFjZ8EE9t4JDBPeqGMTocvjIYd1EXgJAVVa8hvk=;
        fh=r9lVOVGzgsynBGOHUsjL0uC3QfE51LNMR3cW62I/mgA=;
        b=DNDlgsDmObCm8pdBbtiyWWeqWrIZCtL6jGyvaqIMNm7nwQVklVhi9C72GzCCxKbv6Q
         gwHNiDQESshda8IZ5cLJXIDucPuJHx4g/lztGtGzzJhKMKBIuSrnZoKguWVfsQx9QY8K
         6S7GJ0qPBua9Ojh7345/wKR2I/oPr8tietata7Bb6xT7GGOHsJBxVrioz7zY5CIS46wa
         El3gktqw6vbUWhdXK1xkyjgo99Vbs53NFso5o/DXnvZ4cm7pKewWh1LYNEEXPK8NmbLa
         4eqdXAznHx4XbotuEmCJC4mOQSJB7+R1EyKdHjSNmvl6KUl+4dgfQUs+o75EQY4J3RYe
         xr2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VaKJHSLu;
       spf=pass (google.com: domain of 3sxhmaaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sxHMaAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62fa5f13997si61834a12.4.2025.09.18.07.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sxhmaaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45b990eb77cso8078385e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUkGmApzemP5up4XG17TKXpGnTgxinnh9czzMPBN/WO0PFzempE/cy7ssxmfCUW/dUeS8z9t/w3IEI=@googlegroups.com
X-Received: from wmqj11.prod.google.com ([2002:a05:600c:190b:b0:45d:db34:5091])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:6018:b0:456:942:b162
 with SMTP id 5b1f17b1804b1-4650503b3e2mr26525245e9.11.1758204339995; Thu, 18
 Sep 2025 07:05:39 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:16 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-6-elver@google.com>
Subject: [PATCH v3 05/35] checkpatch: Warn about capability_unsafe() without comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VaKJHSLu;       spf=pass
 (google.com: domain of 3sxhmaaukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sxHMaAUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Warn about applications of capability_unsafe() without a comment, to
encourage documenting the reasoning behind why it was deemed safe.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/checkpatch.pl | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index e722dd6fa8ef..532075e67a96 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -6717,6 +6717,14 @@ sub process {
 			}
 		}
 
+# check for capability_unsafe without a comment.
+		if ($line =~ /\bcapability_unsafe\b/) {
+			if (!ctx_has_comment($first_line, $linenr)) {
+				WARN("CAPABILITY_UNSAFE",
+				     "capability_unsafe without comment\n" . $herecurr);
+			}
+		}
+
 # check of hardware specific defines
 		if ($line =~ m@^.\s*\#\s*if.*\b(__i386__|__powerpc64__|__sun__|__s390x__)\b@ && $realfile !~ m@include/asm-@) {
 			CHK("ARCH_DEFINES",
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-6-elver%40google.com.
