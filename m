Return-Path: <kasan-dev+bncBDGIV3UHVAGBBNW7WKFAMGQERGSPGWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 98349416389
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:50 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v1-20020adfc401000000b0015e11f71e65sf5703938wrf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415670; cv=pass;
        d=google.com; s=arc-20160816;
        b=z6wKP2eTg3FnBQJrFp86Vt/wgfGPliKxt66dmPe9xAEqCABLnw07Mo5x8ViuQ99vED
         wChrZC6MjG8weMkxA0a/DrfWX6bCjwUsytxsLgR8JW/5JY4HMi59gW/h31bD2qtoyN0G
         53+sIz/7CXRHySPODT8A7nXbvbMppR0PlA7PM/25OY1wwdmbOV3VlI4SAqnY6oF+7T/1
         aNYAL4I9nmj70L+Uzn+g0PXKZOaldlnTHY8hiIw5p15mb4+bJ/bAyZLmT1m6jpAndo/U
         tQHHSDP5dS2dcfGCPMftLAUVExT/xNe4yIBoraMfoELe5RzwbubUZdGgbHpefj5poszY
         Zd4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Iv67GbRBn+o7D1mBIlc9LwZpi87LMvEHrYo072CWkf8=;
        b=fb/LGpe7wcYA+XWGPeHEvny+N1bCWZ83i2Q+tKuTx5oqYY20SHJ5X7xdF3ROdxnI3Z
         gbeCNuAPnHWbxzmU0RF3y4nFPqLl3VbnFSQzT0nJr0A1Thd14QL+HGlbvOYSCdkcDa5g
         5YMJMkrG4azb6vY487k9BAduWMNnc7Y5+MSFqbI3xg+nTWXVh8kYr6YQm2HJo1jpnTbF
         tAMojHh4PxGOxvlTkV4otprrMzepqhSL7ae5f3yU7tDEr3yZF6gQ8yD5lQXcy7GaC1E9
         VLPz8UZ5dLhkN+p5kwIgK2su4VVsIixN6xCZvfc3vvluMtO/9OruCpl6yzdTUC7zu5AW
         +VEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cfc5y3MO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Iv67GbRBn+o7D1mBIlc9LwZpi87LMvEHrYo072CWkf8=;
        b=KOjjd0Pzlg7P+BYjXpQkpMnpjf2wCLMrqR1N1gAhbYkw5Q1AG2bmMENbb1qZZ/2krM
         8qy3YpHlf7RG25bl7CnT9dtjAbPzO3diM4iw81VJjQXxqLMl1BIHp8ovnI1Fvq4ZUsAu
         0bn1IEY20yMb1Q+G3IY21LV2IDEX2V54VOn5AmytQXPHInNQXjTZbnvlcdPsaPJ+lViR
         Uo/FAGk0+QAFKOWsbl0MZojb6EjFWM2YWTTeKdWCEs1H0ADwCIg58FOl/b18dDEziQPV
         C/ZwSE+b3nORm23PQtz2S5K53eN4TPBzZnF7qDJ7kC1RMXc30R7mnVbU6RnoeQlobGsf
         EqIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Iv67GbRBn+o7D1mBIlc9LwZpi87LMvEHrYo072CWkf8=;
        b=5Sn0inFpLWE/ieOstR3/mfMIur0XJ+MuKbnUIDLq/wL1DBur0VY5GoylHsvRKIEnuw
         /pbvU3+/djYHQcWPFuCMdwgesmatxBc6hj7quFyhU9M6S6wRANCp/cjI/92+cDm53x8I
         gLQFloWRxkJAJrifcy1MnMdDGashz6MdKQZEnDkqz1olWrWuREkiC7ccCc7BJ98bmVg6
         KjcqH6tY4tvtf3dhcFV1e+wxw8RDt8TQN31iyFnNIWE1U8A8MaDzK/Q84uzoC/XgnCyI
         RPePuUogOtjMsK6B61A3TUILntc9hXj/GMgoBMItTKOYVrNaKOE1ikIekmX1aI81Q73Q
         HrKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QD8Gw2v178vy23OEW7mTKoB1TCN+gXJauNGCt1wekWlvx0FuQ
	ubl8HlHgs3DIQphGI93kccU=
X-Google-Smtp-Source: ABdhPJzrniTjPEJj9QM1zqDHgAozqdoSAgcRdmJ7KM5XoGOiBZm1D+FrOgBtcfAvytJp7FJ8iII26A==
X-Received: by 2002:a7b:cbd4:: with SMTP id n20mr5677416wmi.136.1632415670374;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3c8:: with SMTP id t8ls3293991wmj.3.gmail; Thu, 23 Sep
 2021 09:47:49 -0700 (PDT)
X-Received: by 2002:a7b:cf0b:: with SMTP id l11mr5489354wmg.176.1632415669535;
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415669; cv=none;
        d=google.com; s=arc-20160816;
        b=XUV7wmcswosGA7kCse/NT2wtwSXU1kF2uGLrauHXXbMIC3xoOvNo0i1qNFfAhLwGDU
         4gU1agl9h6tRMTPCKDf2yjwQuH0Lt5J9xKh9PaW9E10PvH5r/RDai8+zudVjXNyh8IQi
         cyuqlfqP0X7wDdpZa+9OacBVqBIqRMjX/HwmlrCzZ+WNs9X3vYefvo54uv+D98C++3yu
         iyHhXI9f+oHa9doKva7pjNpwJvnlaMjPUe06xCVShd4YnEzn4Z/itv0Lx9c1EPMbn4+4
         UdZy2I83bQV2mXq5r9T3CiAmTBOkmUQniPZUebYnEpFhFdbPu5632BNRvgKjV5BjtSQB
         DdCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=mB7jM56vMMnOkxJZosiS0/83k5Pr1jaIkmbtlQVNiLQ=;
        b=o5mcjee+wjMvfkns1vWAuzuRrn2ihOLOhsFKB5kNEy1iEublTUJvyDaG+BnlTVAjtb
         IUj/vO1pya7xG3asfTkE9KOUQSH7i4vavfCZQ5nbu70MC8VTbpnOkxCrzYu52kDbEu8Y
         jMnztJ4w3wQzscYzeWaYtZ/5ackBx42NIyTDida0LaRnN3GCgQHXg4AhqaFztwK7Qbb0
         EY0z6+HxLYbnZXFVxoxZ1vmj/n4f+vF2vAWc17EJgpPbJHBoHTK8RMiugRjn95vuFKx2
         5atkOC0MpDsaWCf2ukbR0T2APrueELb2n11Ch4N3Huk43zPsnicTFTFafacgFf1nScO7
         koyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=cfc5y3MO;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id g23si555898wme.2.2021.09.23.09.47.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
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
	Andrew Morton <akpm@linux-foundation.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 1/5] Documentation/kcov: Include types.h in the example.
Date: Thu, 23 Sep 2021 18:47:37 +0200
Message-Id: <20210923164741.1859522-2-bigeasy@linutronix.de>
In-Reply-To: <20210923164741.1859522-1-bigeasy@linutronix.de>
References: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=cfc5y3MO;       dkim=neutral
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

The first example code has includes at the top, the following two
example share that part. The last example (remote coverage collection)
requires the linux/types.h header file due its __aligned_u64 usage.

Add the linux/types.h to the top most example and a comment that the
header files from above are required as it is done in the second
example.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Link: https://lore.kernel.org/r/20210830172627.267989-2-bigeasy@linutronix.de
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-2-bigeasy%40linutronix.de.
