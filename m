Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFUO5L4AKGQE4LXGJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3962C22BE70
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:39 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id g24sf1280500ljl.19
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574038; cv=pass;
        d=google.com; s=arc-20160816;
        b=arA1BwHZa9Wvu/QxXcCAU8GnupYmJBW0mskz8//3WBkaDZ7Q0qLcCJs1aNPXKTjV1C
         9/HDS2IwBE//AQWGEpJjxn4/J2ZmLe1jHV063picZrENktDdM/CP/X82ymRKaIYBfqpD
         /ib4Ko+z7PVnIAXJuOQc1+JM2EW+oN/cWsAtKJTtZEP+Yh+5Vki0aa1PmtNNPN5pOKGb
         S4+Fn50HgcfP6JM+P02Lx73ADONnc/7AkRKP7Hwpcr0SwwW/E50/GtWLaR1emvK3zBRx
         32db6ziqqg2IMON5rtQy97Wkya07fssdfzAxYFHJkPKN9QQnkvgWo3RT94U3LtXIjKQ2
         pmQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ouP/X8Fecr6+3km+7r/oImzoZvajX0fy7puSqBL9WSM=;
        b=oIcPuLlMXQy5bBTE/sfNwdqLFclHrmgMtgdnWknOHf5vThFVC0xXs2BhlmmFynN74V
         mpXhGI+ekpE2/lyenf7m+2a1TnMZxHNnz7ASiswNo8fftpTMzhhT2hONUtJw7vStuDIL
         /96PU98vKsj2cGyTFag1vppEMqKwNh3Oj73/sIMVyNou7ov44jDMqa2N4dFoZDG2q68c
         UDBixJW9cePtPEnzRw9TExE/9p0/+FeoU2n0b6eamqNZQakeHdde/QCMGefYJPbJckvY
         0CFB2WBCrIoEoECqsWQHA0mZgkPv0rq21ZK2bwORdT/Aal7wfNJuBfEbk2IN0DEClg/d
         OsrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=URAz3B9p;
       spf=pass (google.com: domain of 3ficaxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FIcaXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ouP/X8Fecr6+3km+7r/oImzoZvajX0fy7puSqBL9WSM=;
        b=hGi/1einPsbfphgQ5CvEpy14mVgsLajlXpO7FefcH09nexPAr+hczt2NaK33T38A0Q
         0MMf0HccIPTuvsDa6XMEayjalvfQpS0PeJp4DcHccpSi/bKca+YuQvOIfxe6o8Y+9Vom
         9o9pB1zlZ5IKGCSTn6Zk2Lj2xg6RzXqq9nkuq6NpKF/6n20IkIwJV2TVKj/ooraqaFf/
         obg3kmpg2cSD6l2OGVnUSrwn+5r2i2Dch4GUwzMi4ypwkE7RHEH39kJzN1thJDN31yfm
         vuSahYh/k6KX6E4jkNoCzhbLO/hgGE4dLkQisvNwBGT/C6cn0M9WqOOMsGusBzvN2V/4
         ARsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ouP/X8Fecr6+3km+7r/oImzoZvajX0fy7puSqBL9WSM=;
        b=eZ79R7jirk/h1KWUuJZlXjEpyLe3YYUTRrGLBkyoetAi0ktMshgjuKAgpmKBBbUS9x
         KfyiWVVpzzC8EwGQlOFa7tJ1q4fyVE/A4txjrn3fFzi7LcqAiOmCDIISVmsXs4Xl3wGT
         rpDbVQI+KOePznkJowj035R5jyPlKR1yUZ3USRpDYhvJf7+B5XUIjlNKHWZUrXyTJH2m
         smMyiM2Kg52lfBxqCSt9fWlnpjuU6V9uG5pam7iSt6/wO7aolKQlGeekUwQyAQuR4s+z
         3d2I43e7AFsmj6KCXx3Gf+RfCyDaGeeSTw2loqV8njQ9j6pkcnklCf5ENKxejB+28VAW
         Xqbg==
X-Gm-Message-State: AOAM5302t+cvVoEDSKPnSdGXLg6GFMUdZge6hyhUjcwdvYD2qMoEBWTR
	EON53G60Gal1Tno9iv0ImOo=
X-Google-Smtp-Source: ABdhPJwyMF8EHm7gCynGvUZMe4Qgx3uKLjt+fxUtgc4NtiVd+w4vwcNnn3NDU+BY4FdEqgN7bdCdbQ==
X-Received: by 2002:a2e:81ce:: with SMTP id s14mr3732997ljg.57.1595574038371;
        Fri, 24 Jul 2020 00:00:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e33:: with SMTP id o19ls2450329lfg.1.gmail; Fri, 24 Jul
 2020 00:00:37 -0700 (PDT)
X-Received: by 2002:ac2:4158:: with SMTP id c24mr4252606lfi.109.1595574037421;
        Fri, 24 Jul 2020 00:00:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574037; cv=none;
        d=google.com; s=arc-20160816;
        b=DrY8FNrKt42qBP3tEV16Hxk8g/zQ2ZMxjeyPEcmbjxpn7KgoRTw/jYNoZEGn3bDMta
         qcS2QpqNsAoWjKMvb+5wlEclH8fnGJ7rW54O0DMuIFdaJnnCVNamU7l3We5O/PvINhWC
         uEF+Yl0alFm5qWoCWPz7xwE+DwtMBDbBVkOBtVmAqQaSCb30NqoBAwspj28OHDB0pWmO
         CXcL0zntUVahbzRQ2EvYypgAwkJihAdbilw9pFmpALDV48cr44cCRonj+yMVW8LEwP2/
         kE62DfDCLaE+BSGjcdZ7v9xfuJmYKigNcMq2fa9v/985+n6+f0DP8RwGEFVn6zI3wyZP
         KqwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nzPB/8gD7tiXvmPnGkXWvRfHEEqZYmZWnzjoz4lCFa4=;
        b=oQ6VULmhwke7WCwabdn9jzQAFuh60JD8NcupyeorUUXDa8/TzWsXVPft8IVgCpGkN5
         yld9a7t3ZVKcgTNM34U5NN839cXcAE/M7i5VYbwwbPSIaeC+BHvS+62YXHCJY26UMvUX
         FtJ3CtpY1ghQ1qMOvpp7cTzcllm+Qr6O6TntNh8EobWTyZvlyz2wipDNviv410CTyhUS
         Xr/TxR207cdQDohrtjApU2wjzuMwt3akthomxEkif37WAy571NrY2ArzXNcs4v0kgStL
         OrJ/B6SbbVhISKqnw4uAGkCtP6iOryhZ6exnj/nY2Sg3S9Lgi/eWfOkEwv95O/RDU/oY
         64Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=URAz3B9p;
       spf=pass (google.com: domain of 3ficaxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FIcaXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e2si4530ljg.8.2020.07.24.00.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ficaxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id d6so315879wrv.23
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:37 -0700 (PDT)
X-Received: by 2002:adf:e805:: with SMTP id o5mr7608214wrm.419.1595574036687;
 Fri, 24 Jul 2020 00:00:36 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:06 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-7-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 6/8] instrumented.h: Introduce read-write instrumentation hooks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=URAz3B9p;       spf=pass
 (google.com: domain of 3ficaxwukcyst0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3FIcaXwUKCYst0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Introduce read-write instrumentation hooks, to more precisely denote an
operation's behaviour.

KCSAN is able to distinguish compound instrumentation, and with the new
instrumentation we then benefit from improved reporting. More
importantly, read-write compound operations should not implicitly be
treated as atomic, if they aren't actually atomic.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/instrumented.h | 30 ++++++++++++++++++++++++++++++
 1 file changed, 30 insertions(+)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 43e6ea591975..42faebbaa202 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -42,6 +42,21 @@ static __always_inline void instrument_write(const volatile void *v, size_t size
 	kcsan_check_write(v, size);
 }
 
+/**
+ * instrument_read_write - instrument regular read-write access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_read_write(v, size);
+}
+
 /**
  * instrument_atomic_read - instrument atomic read access
  *
@@ -72,6 +87,21 @@ static __always_inline void instrument_atomic_write(const volatile void *v, size
 	kcsan_check_atomic_write(v, size);
 }
 
+/**
+ * instrument_atomic_read_write - instrument atomic read-write access
+ *
+ * Instrument an atomic read-write access. The instrumentation should be
+ * inserted before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_read_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_atomic_read_write(v, size);
+}
+
 /**
  * instrument_copy_to_user - instrument reads of copy_to_user
  *
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-7-elver%40google.com.
