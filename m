Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT45TCGQMGQEM62T4VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 854164632CA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:19 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id p17-20020adff211000000b0017b902a7701sf3516030wro.19
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272719; cv=pass;
        d=google.com; s=arc-20160816;
        b=SRc19aae6soNz6gujGFD3xBmoeQ30KaGyxtEJWcUPGJmWx3PrTmel3njD/O8+MLIUw
         pXqIEZjGrdQp3HFoHRscClXweZZp893UQHeDFlX7cnS+bCUTvr+TtoDH8DAFaE13fyTH
         V2IBo2en4b1Nr+RcpI2DrTy+INbzGMPghnzimm/H7S3QhcZt/fV5IWQU1S/Bb8gOSara
         ayXuEv2WMistDDmnHt/77+YrP/hDY/1Fv+lNbrvqbXvpHC+DpiWGTwnHCg/bkNVwSwUk
         6QFHyISiK3P2s8EP1RCbdlQdG2MmHFQNLRkHI6fwF4S8oLxzswsnMOlMNWjnt7Y0DJP6
         UICA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Q+blJo3CfRm4UC80vdegw5VqZdnjUfN+6FjeZwWs1ZE=;
        b=UCtLL6CpGjLkrsC2QEuvhhyA17t8rcoPAejvRYuQh0/GdcuU4ZZBimUQ78eM7kl1jR
         nJWtDirucqtHnmHABYk/STkmPzEB2hyucAdWTSUcg27rYCpZYNeTuWx+xE3N0Yv3k2jW
         zv250Y3QwCmWFJZtrvwRXQRbeD5qe+SHhMjk0vvyzfZK5sTkF8vLiMdo5JR5YlFVM9xw
         Gns/WBmQ/spweDzjYPdpBwHlfxlPmaQ/NiymWebhBe5L5fpZxw4VLkb1UTqM+FWRePN0
         Xxofwr0ArzDW8OISy8JwmQuYKS7Tr5Kgpctl8i6nMVJSzra76AmtzmlUr/RkyGgpbfNL
         dNHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=clBdSB1K;
       spf=pass (google.com: domain of 3zq6myqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zQ6mYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+blJo3CfRm4UC80vdegw5VqZdnjUfN+6FjeZwWs1ZE=;
        b=ecGqykx0ZUh1dSvvDDTSHrf2IX47IVVApJqP6LZdeg80LnjfzoFEqPA3oUt4Odujx7
         /fCRFRNJ+L8f35DuwDdlg9CueYK4G60WJhu3y+LkhDFKVcOuew85lRrnB296XPGvsRBN
         Ka17F+3KFr2wUjb4CV1upW13zb7BySW/qt4DN5TWwoFaPBp8tR0Hu22F+mWHxpY0xgLo
         ZVDcrvAOrSsiRPC9n52fz2tPl0rDKI3nCEtl27HOpJD5jnAx1s/pKmheO4xIkZFxX3DW
         0rhXDc4B44vK9sOUzrqQAsZZx8fK5JUPxNadmJAh7EW7cJrEoBGZuYTEqyLrFsb/NGh4
         xfWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+blJo3CfRm4UC80vdegw5VqZdnjUfN+6FjeZwWs1ZE=;
        b=FUv5oxRGJiRtIwgAivyeH6rgwCgUcl/+v/R52Vs40eHerh0L4TwFW3dyV34QGNgnvN
         R63g4A3zEFmPXMyrmjsec/3YRQ4cDhRQ01Mr9doKlC5McH6AeUs+IcGdAbByrl+gw8VT
         EB7/z/CjJub+ffbA2k5gP9s68wlHAiShNvUG613EKzgxXaLkxijRHkuT2uHjYzcaESmu
         vr++LE4tqnH0Uqbe5tatkogc9ufbkirnWRXklrthn9UmuEdwgSIXdG007dexLv2XPSFV
         fucJHKSQktDIzyrpmcB2+4FaQIgZsx1dXRlwizenjK4U1yE+xjvCuvq5dLNZqp0AVS+t
         Ho8Q==
X-Gm-Message-State: AOAM532eOUjSZi5t1yrB5bd22FZ6lubJ8jC2y2s2zNpYrLew9bf70kdQ
	be/qGqzBQHopt44wBp+DYrk=
X-Google-Smtp-Source: ABdhPJxavngbQjTLCVAiBs724pju7sZaTrE2dFPWFUaoMEogY88go7QaZ3+rmUCHYJ2niSOKgvMGFQ==
X-Received: by 2002:adf:e5c7:: with SMTP id a7mr40868826wrn.318.1638272719346;
        Tue, 30 Nov 2021 03:45:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:23c8:: with SMTP id j191ls1236612wmj.1.gmail; Tue, 30
 Nov 2021 03:45:18 -0800 (PST)
X-Received: by 2002:a1c:6a04:: with SMTP id f4mr4356646wmc.56.1638272718381;
        Tue, 30 Nov 2021 03:45:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272718; cv=none;
        d=google.com; s=arc-20160816;
        b=EhewMI3Gr2o0XSUkC0K5x12CuwVQNRhDpvLoYiXNWPZHP+ItkZvY2k+EflxdgxRiwt
         7b4AqrEAOAxpRj0V+4P2G+BvpilpYI8iNTRLU7FNy+1C/hXJn9/oCIw4burHIcHuQOfO
         8EtCtJkkV6pS1Fl3X/CDGEFFg483zapra9WMqIGSn0teu/sDEZJPZdnHdBYmhP4kaKYU
         jZZ8RPuj5nkRWTfOQE0yPQyuhEdu9H8uXB5lpYjqq3/rRcMLNJH45BkgbXjeawbU3ZK4
         fMVmbl5VznrJ+wjragrMXJRepIDv65Lc/ZuEpfK98JxARkbVx2V2EGAPVcW3sHfAEnpx
         z4Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=K7olqGN/TGjGn55ZVkEX4B3oA8fATuBzpoXYDPWo+s8=;
        b=kaW+WI2rTOYpJU0b2XEYi8sv4uJc7g+poYxLgqrJsOuNOJcMD3D1Jy7C/gDBiHr7St
         qhey74A21Upn2O706w/aXUKVGMQ0D8/CsxMZA/CXhklBJvcpap4HqP2+MuJlMx8NI2Oe
         YGQgQavBKchEWwKnU2OldD7Wb0mOX5a7dzdrDB1LZbKZF89gR3wmu84Nw8pzOeSq/6cz
         gkuMEBWlikHO3qhvLvxlErv8r/wfUFKuRQKV0dgkR+gEi3L29jfb+ttZc+VPb0eiHn8e
         qk2eAQ9OX/8rSk4qkZZ7LoNUyJKtsHOQYLLvl3Zn7tWi+gmf5LK8fGxre8N4RFNhFMGA
         PzYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=clBdSB1K;
       spf=pass (google.com: domain of 3zq6myqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zQ6mYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p11si166155wms.3.2021.11.30.03.45.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zq6myqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 201-20020a1c04d2000000b003335bf8075fso10323550wme.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:18 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr625490wmq.0.1638272717644; Tue, 30 Nov 2021 03:45:17 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:14 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-7-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 06/25] kcsan, kbuild: Add option for barrier
 instrumentation only
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=clBdSB1K;       spf=pass
 (google.com: domain of 3zq6myqukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3zQ6mYQUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
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

Source files that disable KCSAN via KCSAN_SANITIZE := n, remove all
instrumentation, including explicit barrier instrumentation. With
instrumentation for memory barriers, in few places it is required to
enable just the explicit instrumentation for memory barriers to avoid
false positives.

Providing the Makefile variable KCSAN_INSTRUMENT_BARRIERS_obj.o or
KCSAN_INSTRUMENT_BARRIERS (for all files) set to 'y' only enables the
explicit barrier instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.lib | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index d1f865b8c0cb..ab17f7b2e33c 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -182,6 +182,11 @@ ifeq ($(CONFIG_KCSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCSAN_SANITIZE_$(basetarget).o)$(KCSAN_SANITIZE)y), \
 	$(CFLAGS_KCSAN))
+# Some uninstrumented files provide implied barriers required to avoid false
+# positives: set KCSAN_INSTRUMENT_BARRIERS for barrier instrumentation only.
+_c_flags += $(if $(patsubst n%,, \
+	$(KCSAN_INSTRUMENT_BARRIERS_$(basetarget).o)$(KCSAN_INSTRUMENT_BARRIERS)n), \
+	-D__KCSAN_INSTRUMENT_BARRIERS__)
 endif
 
 # $(srctree)/$(src) for including checkin headers from generated source files
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-7-elver%40google.com.
