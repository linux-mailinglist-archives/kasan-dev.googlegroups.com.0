Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKEIYXTQKGQE6GQWMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 28138310EE
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:11:37 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id b189sf8970865ywa.19
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:11:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559315496; cv=pass;
        d=google.com; s=arc-20160816;
        b=y0teVDXnWzbsl8y8oc1ensT2lI9a4ZqrjaMywH+1S2qJk3fraCbf+XqtzFsl+yKzg1
         Eolvh9HJr8TB0b2RZXrDsPQLVLseiVMx7W14gNMyqIZrHFiMWe25ztT65TULATDMeQD5
         zk6PY7rfKPg5hxkm9LBeWjqbppgUcvLBIt4o4+08/NC7zrUxp8SRFpzZCBl58Y4Srwvd
         jAKuZhOEZPQayWDK6CxMpv+AryGaj8hIBdSBdbPHLv9ibbO1jokUG0iwWyjwciceacRK
         nWL6tyw3n5vXvM0ByjYudO6mhkgSgRc3GdwdjO7nNyAZFZsLZB2GJ1HInW8a1116IhWs
         MLYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=eYi2wejejpFUFxFRpM0oFrRG9GO4TnWN8zvJXWtOUFg=;
        b=GHyPTphg6xmsRtlMlv6Om8AO010KaFGqqu+9o7+tejwmnHdrg89x1yhKZWMabfrMLS
         zYOFQlkm1PFZNurW492HkeXr88XraV6askTGtU4JfGv7TayhcRQzN23xVoy1JqzH3B95
         fdmGyesEKjn5JwfgUF8aX5GvrlLEBe/Jkw/R2FwnY6ESuSvIkDCQL/aXEXXT/aW8u+6r
         pyQQIVLps0XByWzVf70iEdkC4SqKtXd/FAk9ITTwb/IZyCOYF3sKxh/3Xv4ayPkDELEY
         elDRC/z83BRelfnIM7F6YjQ972hSonAlHZzLvXASTKKADwoiir7PyLa0hMGACjGbLQ5h
         iHyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VT0VhU5d;
       spf=pass (google.com: domain of 3j0txxaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3J0TxXAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eYi2wejejpFUFxFRpM0oFrRG9GO4TnWN8zvJXWtOUFg=;
        b=L0HDLvxLK3TXxspUfVcYKdaGwDRX9GkzRGoeScE6RPazUFEWGERislBJ21rmlxQDNk
         0Mt1NDKxsoxFx8O2JLidB51PpVLSbw//8aLs7Qgwtm28bcRD1uccaON688TgXSM9IMiP
         PfnV3Bq+nQ8AcN5jvgrWUSWez4PLKIs6my3p/g6AeuyJ1pUYO8+No1kuZZpneQ9uZHzr
         rvSh+nwugIjalGWScnktl145MTI2ekuARPBV/TDN6gHXs62mO2WKwMD1s+0wCkWUUUrT
         PgnZs/fYLDhKWS4cBXMf6XTWv/ztSS1ow7L91Byb6NPJNPoRUgGZQDt68IEv97Y5kit6
         zqCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eYi2wejejpFUFxFRpM0oFrRG9GO4TnWN8zvJXWtOUFg=;
        b=jad7RVTB2pnjpUYLMEt7Y9oTYgwJpI8YpyQcX2CDjFLn0JxKzkj3DxWXP3CjDiGJrL
         dVs++Bw+p236MbVmbpzK11nl5W/n2EGG88/a7/D5XtlT9tmXUCnNvqeWGLfr9M/cyFyH
         CNrqMPPmhY368Yhu3jkL6twxaFZUy7PhPpQHFp5JorgVPrdsI230iVZjVwfkjNjZSiDP
         AwJdsfbWhMe3ciXQdqCFHSoRo3AERHoa+I8xb/8S/nsxfr7kYyA3XfEnYr/6QP60f2r7
         patdpQsb+0so762yb1zXDjNEZ5qD+o+OyP3jEzwb75+baXWg+7EcU3fSIwtxmjxZwcZG
         vrdA==
X-Gm-Message-State: APjAAAVTcEK2py0S05sOraBo8I4l/7PKQYQdMpZaXJdMDe2jFIPYKVi2
	YGlc+1DhJFGfmoxH3oDqIHQ=
X-Google-Smtp-Source: APXvYqxD6nm+K9PQfc6we7JgwEKNFzLaBVSculTgVJ/rU8AZbglsDs5ghMulQiiNs+jCSY8Zp+Rv1w==
X-Received: by 2002:a25:7584:: with SMTP id q126mr4756511ybc.228.1559315496207;
        Fri, 31 May 2019 08:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8397:: with SMTP id t145ls1140770ywf.13.gmail; Fri, 31
 May 2019 08:11:35 -0700 (PDT)
X-Received: by 2002:a0d:d947:: with SMTP id b68mr5740011ywe.464.1559315495937;
        Fri, 31 May 2019 08:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559315495; cv=none;
        d=google.com; s=arc-20160816;
        b=lCNt/Ll03Cqt4pyFClbHV3lLFtwN+SwDaJMCcSkslwtmlCSrNCEWe2QrG3DKL+mWVl
         nSv6woOlZf4+fbMpKNx+8ddNlj2PASz4OM1R3xtcLxGKSEEXfxvXPNgihNt8MZaY19rc
         xMjBkeJtGwRTsqEA+EBFBa8ujAnxVIx/NQntaiL7HEQut/mWsKGCgfaX+SidxwOl5K5i
         nnErk/VGsLGS7PctUOEe33zz0+yzmxz3ft52SMo/Wo3hffaS8B7p4R6QSo9XvetObRkC
         glRvGH+3onvevOreSNYO3GQhBZFHL76/C3brBgG0KOh7T6SD9ImUH6zRHUtbpn4mVVLO
         uGaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DHrqTUytQArIdQz1xxPzRVqqz8q7l/i/jn+bESY1v40=;
        b=dEQytRNWaW/UQNxg9pW2//CTvou+JmvbbzPJ5QLyu7RexS2e3chfm4k+bQrG387bUY
         JL7/1mWA05FcNHaTJps5ZfwH8zajmwGIWbauqxk4/wWizfJsLCjl9E9GBBgp61/kuqit
         CSnyZzbcpdx/n9Qb9dXAMYXOfAn2hDY8d0wlbTWYlyOq2yKWmXpmSY6hyPUUB6Wwh8zx
         FOVVYVHNZW5V+8n3IvSufnhY5ed/Bt9PMXsG7w2KuxDcroo/BUGSORtUIdWQVbulmpkU
         14nmhnXNUzhSw/N76f2VkwQTnRkLFRV4ZYIC0NZhbtzgKNdKWaqP4mpR4vaeSFElmwWi
         UQJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VT0VhU5d;
       spf=pass (google.com: domain of 3j0txxaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3J0TxXAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id s12si319490ywg.0.2019.05.31.08.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 08:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j0txxaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c48so800904qta.19
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 08:11:35 -0700 (PDT)
X-Received: by 2002:a37:af03:: with SMTP id y3mr9056184qke.296.1559315495561;
 Fri, 31 May 2019 08:11:35 -0700 (PDT)
Date: Fri, 31 May 2019 17:08:28 +0200
Message-Id: <20190531150828.157832-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.rc1.257.g3120a18244-goog
Subject: [PATCH v3 0/3] Bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VT0VhU5d;       spf=pass
 (google.com: domain of 3j0txxaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3J0TxXAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

Previous version of this patch series and discussion can be found here:
http://lkml.kernel.org/r/20190529141500.193390-1-elver@google.com

Marco Elver (3):
  lib/test_kasan: Add bitops tests
  x86: Use static_cpu_has in uaccess region to avoid instrumentation
  asm-generic, x86: Add bitops instrumentation for KASAN

 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/ia32/ia32_signal.c               |   2 +-
 arch/x86/include/asm/bitops.h             | 189 ++++------------
 arch/x86/kernel/signal.c                  |   2 +-
 include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
 lib/test_kasan.c                          |  75 +++++-
 6 files changed, 376 insertions(+), 157 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

-- 
2.22.0.rc1.257.g3120a18244-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190531150828.157832-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
