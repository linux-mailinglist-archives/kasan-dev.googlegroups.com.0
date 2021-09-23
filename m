Return-Path: <kasan-dev+bncBDGIV3UHVAGBBNO7WKFAMGQEC2HQTUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BFF9416388
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 18:47:50 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id i4-20020a5d5224000000b0015b14db14desf5621579wra.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632415670; cv=pass;
        d=google.com; s=arc-20160816;
        b=lmffP/8L/d8DCztlBo/xXafb7sjdb9hkdEpNJnsTYxcYtWxrDEPXQ2HdgGgwWEIoNc
         /lpT9va437OP3hbyOYOuloW4dKrotvLbw7p1aklsws4KqeyfeTfmXgLBY2xL9Heb+Eqq
         sekuwhs+mffkSSXtmGX7DyGpAJarvyny/H9DFsvLG/IBl58iX/PaIwWHNQi3OeFI2BBF
         /IDEGS03S5mGfnmIVFE6+Mic6J48qGPPC/9Z4ZRJnVn8U4sNxW1hByJPCZpH4S/6+o+p
         dZ13Lx2Oo3Sm1If2bKPhYlR1fbDCisuKHt8jvK8QyolKh0GL1cYOFGqjZ6guIsZZcByT
         /0Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=e/55zlrtKav5Iun/aIc36RvuGiMpFPjI+vlidDXhyDY=;
        b=sBl1xvX5+a3/T6D1cqMA6Va27h8pLUe71whI8ualctdiruRe4SzuPDeelU82C6/vRW
         SYkc6qbNazFrfwNpjVpXz15+0LYx3krHwuBuzjXHstZCG+xh91UT7Jl4Tjvz1vABAbcE
         4LZmptM3uI0bADJQJMJefP8yqKX2scE3/SJMB7p+vDDD1ayXN9qIhK6ZnRZYI1B8H4z9
         J6Hg6OgF7Z8BORqgo75I5zXjayqOeZj6Q8DqY9hNcVzq88SAI4zG4dd41R7Yi02qvpwc
         cqFDyFL2/gm0mPr9ZYJXo9FpuG58S8sJ94j7OF+FETvCS40Re+6an1QAZ7yi+Nd2/9UY
         XbMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=nBMrVpde;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=GZXPr5oO;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e/55zlrtKav5Iun/aIc36RvuGiMpFPjI+vlidDXhyDY=;
        b=Se8Wu+EWs8rpL8PJewpM4Faq8Xq+rJ487hiJq9lqwWmFDgTeVNMa9iQRFx5h2VreVq
         meaWF9OCUrdX7rjWPuolXODv3oolMlqVlJYvRnP+nV+Cghzv6ZPPz7gisTcTAYr91dAT
         FSy0hcL3QXh4VwWrHihmul1hi++ke9X6TcNpVeaqWKsbwcezsvFSQCCt096o5cJq5/DG
         h/N0OoBdmw3a85nUI1g5Wj6zO4Hf7QG4IadMQceyy2LMR6kctYdg/c3lj/jBK0VBbA0t
         J7YXmKASoXWXUYryJJXqwNpP/kAvPl1pKi0I27LSDz+jNQ0hMmHQ+tk+r0Az6yFFue/T
         64Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=e/55zlrtKav5Iun/aIc36RvuGiMpFPjI+vlidDXhyDY=;
        b=cq2oiPSdhC2h0J5g9M9mWt4kPDUdFffbdBRBSXOT7uKakuMR0oDB7agL6bXNIBMRCL
         J5qtqcgPJ5GrRTkszTBUuHHmfHHxTlTe9v/FoqrjrXyb0dJ6gqpyAqpUxuE1PHTDS1HK
         AxAnTAz6egRpTYN9Lz6VT4ZUEEztUy+fl8hxnhKLn4AgV4DOhk1Gwu7IRhMt9QZKJMj3
         mrDWltCuqDeOhY8DKoIeiDV7Z1IMFZfh4WgXpK4EQd4IsMJtCgHwMliOAYE14kfiBt5J
         vuv48enyBRjhU3i8wUwvVcE++Yy8TAiNAP+2DERG4Pg0y/2t9mBuLtfElgVjpApqwm26
         MOtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533EisdBkjGTto7/Afb9lv7oSA4kZoSHqPWmtRmpMfBvGfRmROH4
	u8jEoifQjczF4Gkd+/D9KxA=
X-Google-Smtp-Source: ABdhPJzUX1lGlwAtfhDeiVLXLgpmQUnkaXGHVdGxtxofzkTbrRbCkCBC6Y3SDx45Z9Ncd1OCyfYBJg==
X-Received: by 2002:adf:f00b:: with SMTP id j11mr6477131wro.184.1632415670125;
        Thu, 23 Sep 2021 09:47:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9bd7:: with SMTP id e23ls1369705wrc.2.gmail; Thu, 23 Sep
 2021 09:47:49 -0700 (PDT)
X-Received: by 2002:adf:fe44:: with SMTP id m4mr6524621wrs.206.1632415669283;
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632415669; cv=none;
        d=google.com; s=arc-20160816;
        b=myT0E3lGyaLSuStTKCdr87gdnr7UsCF3Pr6+LZAX90O8+bvIRZdcNzJ4Vb9S52oE1h
         V5zJfJ+iszi/EpAM4hPCp2z65v/C60B41ETQwS/XrLtoP+JomEbgizkTFmCM+xIigxbX
         g0Xh+ads5SlLaM9YjJKGhJOpWgFMg1smznBfUhJ8FxhAsEOCbIsLn0sTMJkHBMFz3NCc
         uiP3DyJlkTlzaZzjt7UA2WCLisZ4anOQVPvNEmve5kVPcJMhxKEtkH9DvNztnp6dowGG
         h30F5HmJ2x4ivlNPUw7CUnc/e14WigPF281Xzz/+r5iAENrhNnlrwFJVkCAOIBkPaWAD
         jm7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:dkim-signature:dkim-signature:from;
        bh=y0wDMkgnV956fboXQ4HXhkXy5kQoth5WK1arjbx0f5k=;
        b=n2RnG036WcnuVYJyHUzEo3PjNaBatafyfGPLLpkltpOEQxmnGKNQzh2KSb4uRdjTTh
         nVKdTLuohNKd19LsRaEkb0MCnRYjzLI0U2ZIhCWZTOrY/LF/Tay8mJFDnzO+M8Y7xLXn
         9rShu/aBmWp4VqCpTZjMR7ddLv0RpS+nM+0QYDlLG2DvnzJ/xioTp6N9qONKXVEkmAzv
         OxI+NmVNdExi1aRmCzKj6TzY+OCrhl9ogCUvUSOOZOhq+PkPdQuPwOBeB6t8xCEOS/Gj
         urdHMu5FIPUeqXgu1etKD14tWGj/DJZv+cIksBKx9IgCrRC0vhwkB1YsHmfKiW5TXsCD
         hzaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=nBMrVpde;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=GZXPr5oO;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id s76si860475wme.4.2021.09.23.09.47.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 09:47:49 -0700 (PDT)
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
	Andrew Morton <akpm@linux-foundation.org>
Subject: [PATCH v2 0/5] kcov: PREEMPT_RT fixup + misc
Date: Thu, 23 Sep 2021 18:47:36 +0200
Message-Id: <20210923164741.1859522-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=nBMrVpde;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=GZXPr5oO;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

This is a repost of my initial series [0] with collected tags. 

The last patch in series is follow-up to address the PREEMPT_RT issue
within in kcov reported by Clark [1].
Patches 1-3 are smaller things that I noticed while staring at it.
Patch 4 is small change which makes replacement in #5 simpler / more
obvious.
I tested this with the snippets in examples, Marco Elver used to run syzkaller
for a few hours.

[0] https://lkml.kernel.org/r/20210830172627.267989-1-bigeasy@linutronix.de
[1] https://lkml.kernel.org/r/20210809155909.333073de@theseus.lan


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923164741.1859522-1-bigeasy%40linutronix.de.
