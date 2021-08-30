Return-Path: <kasan-dev+bncBDGIV3UHVAGBBTVJWSEQMGQETOQO7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 718703FBAE7
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:44 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id q3-20020ac25283000000b003dedfdcf716sf783928lfm.20
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344399; cv=pass;
        d=google.com; s=arc-20160816;
        b=VbrzzZAQOa5Rhkog2IAis3p4weXduJuDrPHpWNDLeGh6YrxwkpXkjgu2WCX+ZlLIOs
         bzCKrPe0F0He0czcAxi4yUd76yUno94R6xz2qEqLP8xEPXoYmZOEx/t0iJyWorTi8Jad
         OR9rhTgyIWVw5UjX/K33hnyCYPZAgfJ1HShHPiXjMKJBFNQQMcVD0J5qSi6OjYxsS+rn
         euEXN2U7KS58c6QSE21bAW/dBNIaBpVx2/jd9V02PL2XCsz6jL1ESbxod8DY5KrTIyX7
         BNEgJxaut9rhZ008P+DQCN0D3pgSbj/fk1WTlKIuCWW7bE2k1/+YrLwY7kxWvAvibiU1
         Ll2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yN6UlzVffXpoVMolIoMOptGUljyRxSXCNKBHykJTVTU=;
        b=i5I++KD3dZ5fNBxvYJ9LEr2/+hGFqmHLBtY/6o7XfUQ7ZKYdYRL6DSjhkCF1eHO2ZT
         GKaZZpvL5LHgDk55T0FmWbIyYGjmpOL7ZxQFbAQnUuxE4OGKX2OM9OTTgjMmI3XNfwH9
         v5Fz6msZlodQfP5m09SmcsOh6jLZOqiCxSBVls6zTA7+sZQ+ISRnVPa7yfCaZp8vZRsb
         eTIhQ6mugvKyvecYHr5AGkJDefv/HF9fertAtjdeqwG+MhHp9BEKr7ZbIXRs/BHpEq/p
         UZGwCa84ssiC6hRTgD8dbkuGiW2q55NaRAraSURgma8ptYHvx5xXwUlN0ypmFAzII4DS
         PfBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=rMgybfzV;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yN6UlzVffXpoVMolIoMOptGUljyRxSXCNKBHykJTVTU=;
        b=TC5FVReaoEpJNY5g7aCvYFhLODudOKhO8+SVFsHrKF+RRXfw+0iRBGj62L+EjwdYex
         E5ATuB7Aq4JBWx0Vwni43Hofi5p2FVH1cxOkQR0miLzrUDGxh231D9kEAFtk7PcQp2jG
         1twaNqiFzI6HDDAhUYBGaFm71SSrh4JAVd+E/NacDViWTWP2OkyIC7YBxq1cg09RDRRp
         2H0h6W7XH2gZaBq9BhHTIxPuf+34J0zA5WUAwfZIy+Gl+RsCg1OE7ig36bsZEyZ0Sjfm
         CU92Yga6GmADenlshNARE7srGpUZczT3hStG6WUA5gxG9UOyUEnsSE3xTzc7v58ywJNK
         I4dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yN6UlzVffXpoVMolIoMOptGUljyRxSXCNKBHykJTVTU=;
        b=KI4emo7zBnz0h4v8hsaokX09eYPRdtsVpDN/OMTLzFAKGtyTGplFt5Pl9KwmxN6Azf
         HxHftT4kYCl7+3jpapKXrxbe1P+iXckaG0Sefn20ygpCLqmXOaaliiw38JCCzzwrg+l5
         TrS2+dd07j5tUuI4mgRv2kGAGmwIKZq7On9D9I/DVdyr/JLgtO7YLYZ2y9KZtax3D0Of
         hY6jiTQhqvOBV0ZoWNEqQG6Jl4dqReKeFHV6Dotjq1ym10P1S/AtKh52SijEAfi4Djm7
         s2eosJmrwpyUfRDJMAMp5XBrRdIx530xL7WBcm5njybJnifbovv2esc8Tuo/mZ4F9VZ0
         uboQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XiZoSE3zF6HFfDlSYyMuiLPY7tOUQR8fsfreVmODYvPFP1LpG
	6u8ICQcMJn6vd5TP5f9WX+s=
X-Google-Smtp-Source: ABdhPJwKO4I1OAI1wjBwKigsbhxyR0fv1M2XR+79t5ClpPxQRpOM7PVYe/t7ljQ7vlE2CV4VArJO7g==
X-Received: by 2002:a2e:9901:: with SMTP id v1mr21148888lji.205.1630344399000;
        Mon, 30 Aug 2021 10:26:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8945:: with SMTP id b5ls3234736ljk.8.gmail; Mon, 30 Aug
 2021 10:26:38 -0700 (PDT)
X-Received: by 2002:a2e:a5c9:: with SMTP id n9mr21258022ljp.131.1630344398069;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344398; cv=none;
        d=google.com; s=arc-20160816;
        b=h6MK2YK+TfRA+hukZOEFeRw1tiXVzEOmiA92Dk0sA8wLadtHm5c3KGfmxQOmXzh3wy
         /MjAHH7KHcuo6iG+hnE1HfbHdYl2uq+1FBkWpHFtBG8piCRgeI0W3QrzpPVhndvkIhee
         b50d2dvmZVwWm1nBdi4xXywWkVAWMJMvfhelVu20mjphs81j3ADPLy+yquvOS/Z/0F+Z
         GKKcOefQ+Er48FJ0K5DzjXzOUh3lykRhEskt7OTpKz7ZI+xFpk2UOKZx5/obTa0GS285
         cAaMD9UI0atbjtKbjbuuVkEo8T5b7hYkLMYIN4yNt6/hQnLuMrv1OS7gP99MER+Eb15K
         LCwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=0+iCVw2IvZlDKvXr97WaRJSIP+szLJCPLi2TohXxcYQ=;
        b=Hn/Ulr8xELz/OdWi0YNv+0DoWYlJlcphDEoBvRC31CLUUdw5Vhx7vH8frRkHUpaOss
         pcFnkEgRrRs8LRJWem7nsr1k54IRH39bHtRiwwg61qYFmfTeN9231ZogXAYboiQG+YHK
         xv9jebF8hWTtF7gElRE3EK5JnupztjuFU65gir5DL9BhVfvgNtgU42FLNmrjVKNXkP2g
         MPYPqKnUSzpaRPaNRS7ecSom19p9poe9Lmpxyzzrb0dFcLqnH1NPrVqoMibZouwl42IE
         s0K5CYbT0o5hN6OuGhUraYW9uluglIvlizHP6rLAPXX2aPRTHhfP9KIhvUvDhA8YmTJ1
         d5/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=rMgybfzV;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id t7si261454ljc.4.2021.08.30.10.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Steven Rostedt <rostedt@goodmis.org>,
	Marco Elver <elver@google.com>,
	Clark Williams <williams@redhat.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 2/5] Documentation/kcov: Define `ip' in the example.
Date: Mon, 30 Aug 2021 19:26:24 +0200
Message-Id: <20210830172627.267989-3-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=rMgybfzV;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
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

The example code uses the variable `ip' but never declares it.

Declare `ip' as a 64bit variable which is the same type as the array
from which it loads its value.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 Documentation/dev-tools/kcov.rst | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 347f3b6de8d40..d83c9ab494275 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -178,6 +178,8 @@ Comparison operands collection
 	/* Read number of comparisons collected. */
 	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
 	for (i = 0; i < n; i++) {
+		uint64_t ip;
+
 		type = cover[i * KCOV_WORDS_PER_CMP + 1];
 		/* arg1 and arg2 - operands of the comparison. */
 		arg1 = cover[i * KCOV_WORDS_PER_CMP + 2];
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-3-bigeasy%40linutronix.de.
