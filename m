Return-Path: <kasan-dev+bncBDGIV3UHVAGBBTVJWSEQMGQETOQO7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 463823FBAE5
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 19:26:39 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id y5-20020a0565123f0500b003e21318cde6sf640635lfa.11
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Aug 2021 10:26:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630344398; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mksh89SAvaiMxlKwAkEyow5z6hqU8FpyaneHYJVU7PGIAjphOe//qm/9l1fimSlfDE
         UcdxfVGVXYngVdjiO0kdKh1fPa70mKrIOZKn2PfbXDNu9AgqqOExJerdqJRiN2ppWMSS
         2ub4srBfzeOkZNu4s981tIUUDmSlPyajjfLOLClVtsa43LrR0dIBH77pjay4HmnQ46ic
         oRZPHvWEx8xqkeN/bDU5tRh5W4GQPt3JpyIm3/J+Qj2IEcLsPnwnR+KY6InKD7dBxFxO
         6uqXTTBJsvS3bgvCjvl1gCFljYVNgiaqypKm3vRXSLf0lyLjswYkeyoB1+u0bVmfSSrW
         WDAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GKTFDwT9OdFi9H+qWP0nh1PspA5nY2me4M+592vAQlA=;
        b=b+tdBpuZyeMsGvJrzfOBi1iKl2SRuzC1LDAIiZd46lQepT7OHM0YtYxcFzF5mgChwS
         UhltcOSq8iyyrZbZZTVyyRPcsh5WFtxPSc+jQwB1430wVD/csbL7L1DDhcR44nyJYdts
         lCcw4IlISqjK3OUyaRmRVyPp2/r/w7Ulys36kN1R+TDztS5MNGz6fq6Y82RUQRDg7J7K
         zZJ18lOPksxa/9OCA/4UHpyQkxco4zTFsApnzVZyC0xqURWG0a3Sj/eRu30b/2U+wUX7
         9hWR4KZTIO8vb4b8Pm/IXq7m+WLPSWTWgTotLc2+7Q8ozNKVLDqSdA7E+hszWMUVfKjx
         BPXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=1yWhNjZt;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKTFDwT9OdFi9H+qWP0nh1PspA5nY2me4M+592vAQlA=;
        b=m88E1bqIrxOk7a724cPIEMACnu9g5pdrQFVbzB+g5dDGmgTWGPVbTmLNvLuOKWudOG
         a+1wliW1sbXvhoZO0EL1pUbADboK+iaUkCFedRf0ncx+Ujjg4JflxE0Hy/GBhZ3rz26n
         h0KkwgF8c4EaErudA/3rwpfH/kBGI1Z8gARRfyxdBWkeHZRVnLCg3tGZYUkq9tOzWNDF
         fw7OscLxzLBICS6kw6jZGCf9HVF4NlxH3S1QPa15fpksRD7XsEBwIaYG6T20pjYUMMkA
         exjGIGu2R3iowWisk1fXDbol57ndTsLHihQhD+o5ASqMpG5al4s1ey2xuIz1NPOkBl0b
         5cVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKTFDwT9OdFi9H+qWP0nh1PspA5nY2me4M+592vAQlA=;
        b=CxMcmLBhzb7f6zd5cb9MlhRybdRDKxsu2/mg6KId+rNdAMRFOu/Xck7AvQ0IuMjTFj
         lRNP4VMFc9l7/mo+kgiI+Nmt4gS+cqKASAt/LD38lLPv7jYIkXknGmGFjwR8tKtLuP5I
         6qXyyMcI2snB5GMPhR9qeIMHi80dXwTF6uKN01oyBZH7mPba0UQcCh3Icf865M93iN7Z
         pYrasDGZwmPJE+iPCd54J7L3DeEZBrWX6MA2PdFxTt86Y1m+MvRCKaQiRcTz8TIwLNVP
         75nKjEqCYXeRQEqGVBP8CnNwP7ZD2ZpRScuuGkeNFR/8ka4rJ2N/NwglYvG9LuQuWh9S
         F1fA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FBdep95Luv5X4wpuiElpccxRBqSnOx/1gnMgg0pgQGMefZPo9
	d3icYnsQAzU6Jf+/X08YPLU=
X-Google-Smtp-Source: ABdhPJyMJD9FdPXbDKC5H8ss5i5ZMIXmYZzrFvsa2P46VG0gB2iQP1koNIB/B1abFPFjx4F01LkTkQ==
X-Received: by 2002:a2e:9049:: with SMTP id n9mr21669495ljg.425.1630344398737;
        Mon, 30 Aug 2021 10:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2119:: with SMTP id a25ls3233465ljq.9.gmail; Mon,
 30 Aug 2021 10:26:37 -0700 (PDT)
X-Received: by 2002:a2e:9150:: with SMTP id q16mr21141032ljg.418.1630344397643;
        Mon, 30 Aug 2021 10:26:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630344397; cv=none;
        d=google.com; s=arc-20160816;
        b=qB5+7wU/fLgAIBgUoG0uKOWDHxfc0LcqMvavrsRDf5BSPy03VI5rXQieYqSqgcDh23
         qWmhZd9kgM4f6hTC/LbJSkbwXcmRmncAeOU4MZCguaPBCU5ojuuJBlh/eJae05sK6Vah
         rW5TRBnX5oM+Kus2XKx93uPaDP9Ym9ziuviyaZkBwnqY9IaJhFYwyO+Nch9vNVte36r3
         r8L816zGmj1nc+e7rC+i+aFjUiCPmPa5rAc5YIR3L341Jk4hJHsDx1TJzjm/2KZuJeHt
         8Xe1kFW8EvpugkBUUE8VIXoXb6wY7xub/Sk26GqmZJv07d08RYAdddh3Pq4tgL2p/2Og
         UHkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=u95bLI4q4WJi0Y0q765P3HlxxgiU6jgiCxI29+0MUC0=;
        b=pqeXtCxBlF8Z78+jouaEnJkB1peEgIQnJweTywBglwcKFp0N4qz7UwDj5hiBO2wl5W
         6+sanOI/b6VRIJ1gUOxNto+176KZUg0cZtl2mDSA8Bla8T2YGImsHpX0YnLEvnJ/5bzQ
         ZChH9Jom27oEpwd4OhejF8WEtD9Vj3r5GF7usLhSi2PE0Ku1jIlpa+BwNgk+XXncvnKG
         a53IrWD2bMZFwgWS/JjvOPfACZ0TlNobe00W/Yw1tW4+ch3Hka8AcoMadBZxoQcPnQG4
         +fPMjR35c29m0/MgeBG+bBz+2y71dUlcMSBTzoXt4Cx+5w1Rk+8BsePD3vWK5ZSUT5E4
         BFHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=1yWhNjZt;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id e17si832017ljo.2.2021.08.30.10.26.37
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
	Clark Williams <williams@redhat.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 1/5] Documentation/kcov: Include types.h in the example.
Date: Mon, 30 Aug 2021 19:26:23 +0200
Message-Id: <20210830172627.267989-2-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-1-bigeasy@linutronix.de>
References: <20210830172627.267989-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=1yWhNjZt;       dkim=neutral
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

The first example code has includes at the top, the following two
example share that part. The last example (remote coverage collection)
requires the linux/types.h header file due its __aligned_u64 usage.

Add the linux/types.h to the top most example and a comment that the
header files from above are required as it is done in the second
example.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 Documentation/dev-tools/kcov.rst | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index d2c4c27e1702d..347f3b6de8d40 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -50,6 +50,7 @@ The following program demonstrates coverage collection from within a test
     #include <sys/mman.h>
     #include <unistd.h>
     #include <fcntl.h>
+    #include <linux/types.h>
 
     #define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
     #define KCOV_ENABLE			_IO('c', 100)
@@ -251,6 +252,8 @@ selectively from different subsystems.
 
 .. code-block:: c
 
+    /* Same includes and defines as above. */
+
     struct kcov_remote_arg {
 	__u32		trace_mode;
 	__u32		area_size;
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210830172627.267989-2-bigeasy%40linutronix.de.
