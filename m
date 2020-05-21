Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLM5TL3AKGQE4SRAWHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B701DCF82
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:39 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id 70sf5356190ple.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070958; cv=pass;
        d=google.com; s=arc-20160816;
        b=jk3mhx28QPLcAFOfsRSWK+Fcrg5a68DEcGD6il9GHraAk2jlpjUXfozyZyUGGGwFlW
         UK1KflpPahZznlnswUWN4ozD0p1WnAebDWmJcEHC4XLOd1+Qz99DzPWwmlHbupNDPOg2
         LW76mQsp9h61vNlt0pc55kaOgDPb0CfdpFEz/p2+N5oB+SyUB/HMXp2IBd8c7ujwDRsT
         8sk+0TM9NQ360RiQ8HjCO+JjlBo36DD6qqa4vRwA8OO5br5mv8D0VWY8J8OeNqwxmCLx
         aeQ5iwZs+TENHbjUnt7iGKSv23OwZZy1KqoixJd813ragehvCEHHzRHjIv9SQy20r3cZ
         W1Pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=raFizLr5TK6CIR/7AJoTbYq8nsO755wTt5syGrts0iM=;
        b=Hr4ZU27lTpWEOH6njlQ2Sz7OqgwqBz+wRQ9HosmNbxPViZmO4OsDzb3OJLZoiviFWL
         WgIM+tehKlGAqi+wR+0UlmkQCt726Rx+ldT7EHyLmu8SF+I3ETOP765eOAYpwf0fewAp
         foh7dFb8ip6m4ThWFkUS3TJwTJXmAh/dtdNQA4cVOBnJAut8LCgEi33ZuhusMnwJ3sZz
         RQCv3Xokil5m7fuBVeyySz+ZXCZxd5rfxKOgRPo+9WZF9BnUpnVt4qdkr1d21OkZIfYQ
         hdTPfXoSmIs77J654L/5RVoxiDFib68m/w8/MnnWsKMc6NKVVHCvdU2SR/t7JrVnVrQd
         YcHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AousQc5p;
       spf=pass (google.com: domain of 3ri7gxgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rI7GXgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=raFizLr5TK6CIR/7AJoTbYq8nsO755wTt5syGrts0iM=;
        b=toexRqIoOclf0491dMQbTB2RuJVe3XhXAeP3+QfecknVzkHYwsJwwE9oRuPX2ggaxj
         iDM+5PGog6A+TmVt3FHx1crcr86/QzKzNsGutwE4e893TwElRMHZ5JghM6nta9L8PQgR
         slgSFA9wi+6XdBq41guIyBqgnXiOd9UGIkoRv66DFn+lchqbWlj8Yj2mOGcIDcPJKIAH
         lqwAphhFqN62ryBbPuXOFFuWjqaTVWIZ+DMNi8XjRPQsqVZAKK+qbb3mY1GWEIdaTmI9
         085gDPU+aOo+UpvrOYxtOsy5xzazu2gsM6cBkTIDsuLpB8s/+KvRKezZDVYUsuFYb/7n
         3zwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=raFizLr5TK6CIR/7AJoTbYq8nsO755wTt5syGrts0iM=;
        b=pGQBY8oVUQOIecEH1I+tbZxqZ7QRjH2M3/18TsbPud/BtgWfVo0UeDKjBTc64DbD2b
         I9H6qCTmbGrPJoX02D4ZRsi/BZvfUIeAj4WrVhGqK+oIOPQsKW2kYyDpPKImfRKoTn7g
         2oKqk6pMRE4Oew0Onbz/RYOOp1TZdYbJSnEm2j+DxIlTnRlChNiHHigIwuxSoQ45GSTV
         /3ebSL1Wr3Wrsr/bl6QFc4UvNJzc948pITYSmtw+PNmpqHlniniD2nCdgSjkW+UDIijY
         umHhZe86UAxjiTLEdkuDJKHM31VT/3bxC//DIiWKVYMvukITsi8eh0Ubr+3ABhqCW4FB
         Llww==
X-Gm-Message-State: AOAM532gmUvby+5YQVAQ5gz3QAx9oWSMgpIZsQ+vR8KjxhS3iygpVdgG
	X3aXPAsMi9N25mmge0d+isE=
X-Google-Smtp-Source: ABdhPJzCAAO9EVhaG3LLsmnU0WlVxiCHmr+gcBfRSKDuzsL2wH9c3wxFxJlT1yas7WFbCRUAnK5oyQ==
X-Received: by 2002:a17:902:fe06:: with SMTP id g6mr9652065plj.118.1590070957893;
        Thu, 21 May 2020 07:22:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4b5c:: with SMTP id k28ls752832pgl.0.gmail; Thu, 21 May
 2020 07:22:37 -0700 (PDT)
X-Received: by 2002:aa7:94a9:: with SMTP id a9mr9545950pfl.312.1590070957461;
        Thu, 21 May 2020 07:22:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070957; cv=none;
        d=google.com; s=arc-20160816;
        b=I36NUwvTnoNKjX6QVyjDhEthbHCBfPKAjgp3X2vpF4sGorJcixQmp4JCbzDWkd3wHb
         d4Rhgqmia2KP4ZJ1ds0Nn69CB5KW1B6hA79ABgFuKxL04XdnNFyPOD49kohiDpqvjZ/S
         2lqH8aVlQcXRUm75l9EFojliw9/ordgWTlUVMz4JTo9jfQkW0jw9KTcMqUA43FitKmEa
         gqAVRbfbt/Ta9YGqFdgk94+O+V+h1CFiWmE/tziu7iwa5hx6m+UD4oLKZc5nRDAROWpF
         8TKcLs31VU/WeVVrOBR3e1pmqiddDy/ufjOux7T4VPqiHAAQMJ6R5Sn8byW/bZm1dQDr
         awtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PgDY4jBoWDmqeTjpUELiZyK5eYsaiohYt+3kMWavVjU=;
        b=xjyi+HA3nZni7k4GzSJ2D8Zoc79f/5SWhUT0lwc+mbOahdIkBOsEQ49v9PsPA9bhjr
         ZU3xpgvChJd051FFshe1DjnlzIymLnrWlRKViyOWtSkJ8AAIpgZp3UisnyGuOj4Skt+z
         Q/xr8kNNNU2awDQIQcIFSfV7XoexycPR71C276WWgWhT8vnNBmneHf5Pz99sDhiAgG8s
         ZEyfh1WGBmxYXWNdk/cf0O+gfQGnSxWqJHPcGr/ofTCKn2pdFOq0Vnqkuynay5j5B4pv
         3aOdymw0nbqORrGKvHzrGLW6VwKuUoaCD+kooF3WqxGboPI8JbcPEEQYnO+LiSYZDCL5
         cg1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AousQc5p;
       spf=pass (google.com: domain of 3ri7gxgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rI7GXgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id m81si623939pfd.2.2020.05.21.07.22.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ri7gxgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id g8so7787469qtc.22
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:37 -0700 (PDT)
X-Received: by 2002:ad4:4690:: with SMTP id bq16mr9884082qvb.20.1590070956501;
 Thu, 21 May 2020 07:22:36 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:43 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-8-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 07/11] kcsan: Update Documentation to change supported compilers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AousQc5p;       spf=pass
 (google.com: domain of 3ri7gxgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3rI7GXgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Document change in required compiler version for KCSAN, and remove the
now redundant note about __no_kcsan and inlining problems with older
compilers.

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Add missing commit message.
---
 Documentation/dev-tools/kcsan.rst | 9 +--------
 1 file changed, 1 insertion(+), 8 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index f4b5766f12cc..ce4bbd918648 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,8 +8,7 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0 or
-later. With Clang it requires version 7.0.0 or later.
+KCSAN requires Clang version 11 or later.
 
 To enable KCSAN configure the kernel with::
 
@@ -121,12 +120,6 @@ the below options are available:
     static __no_kcsan_or_inline void foo(void) {
         ...
 
-  Note: Older compiler versions (GCC < 9) also do not always honor the
-  ``__no_kcsan`` attribute on regular ``inline`` functions. If false positives
-  with these compilers cannot be tolerated, for small functions where
-  ``__always_inline`` would be appropriate, ``__no_kcsan_or_inline`` should be
-  preferred instead.
-
 * To disable data race detection for a particular compilation unit, add to the
   ``Makefile``::
 
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-8-elver%40google.com.
