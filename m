Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTHA6CFAMGQE5UOS6FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A3B3422435
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:29 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id x14-20020a5d60ce000000b00160b27b5fd1sf1235984wrt.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431628; cv=pass;
        d=google.com; s=arc-20160816;
        b=ViyNvUyiRkLnaxmnhI02B3U/9ogJ34EWgTOgt1R5nvaLhO89Q78Ioed3aKYkkG+YSw
         rlJMByKDBfPGNY8PFi+SfsltGgZwMgOc0uFstd67bXEqi2rSSGptmik6UNAs4oopg1Ou
         qVZZNfTbR85do94mbuowufFvVJnqJ8udpSzeniM5BObIz6gyUbqXUXfWHEP6318d+xYV
         Gg9vAGY6V1nD4A4Ix7ikl42bfAVdYPPSiMTW9Uk0EJrr5WGQ5H09fptgvT97lQNbyXD3
         py+Exb8nLPqeS+UreDKG3tFmkxTgNGCw/py+EI5x50FgmgtWRqCAczcTRxEhB8cMF0AV
         fhFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=VoPDnlMls0bxYI4yPcQrNWyDvNTwRJGkKO8wq5DYo7I=;
        b=hKLEIGlFH+TC9kDcb1jnKzIIPZU2oUODp8IwwaEQ/t4ywXBJcBEHhlg3n+N5zsAsIY
         3bDhF8lCpbzbfpXZR8gQkeJI6FVPo8Q3QMQ3tcnxtAQYIRuL7xqGJqhZ/C+TZuScU2oG
         s4Nco3f52VXHIly/jv7Lz96G3J+UC2NSPkbR0QhIFdV8IxI0/2Pd1sp4E7aVs26/GlrJ
         RL0gWRFT3kMJE2/hUwPfZHgbkB5OnfdUv+so+90vVdw0EmDj3VncFXc1ILUsITh/2Wk3
         L2YiL3yXTBC3BIJ2jZEg2WVET1gBq6hk9ujmzOTy/Jw6IojU22LjvRpuf7TdlQJM0iCN
         mx3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZfIqlUU;
       spf=pass (google.com: domain of 3szbcyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SzBcYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VoPDnlMls0bxYI4yPcQrNWyDvNTwRJGkKO8wq5DYo7I=;
        b=plgBZ1rZBT/CaNrsbX/vGlGrOdw0041UD0IxQWOFKYfj94iAToNjNdwMQNVMVIypJx
         ++jAsXGw1oLsrfWx8MXCxyztYrcs82EpPfIXb6P7WxgA4Kbah1s4Z02jc9yAyqNTrKVA
         pZcb9HRp3kQE2rhWgutve8PBlMCegkzuwjbiipcGIVlEB5I/64V0F9l2om3nQrY+e4KZ
         GIdN8/zWSS0Dg0R56arEdPFGEmU1u5nqshBvWCl82suhXO79Zxu6Bv7rR0vSOQzhXIfm
         AGBwhizW//KnqPDV6dhyMjOZ3vRvRxlb+Fwe4Vnk1jfWnaWxwo+sqA227CDecBKLTs5u
         CWdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VoPDnlMls0bxYI4yPcQrNWyDvNTwRJGkKO8wq5DYo7I=;
        b=qpExtB82WMejKZsUxwaKBEETzrOhzfii4f3PDLB5gn1KVOfBxsr5tkt442ZSJy0vc1
         Rg3dJd6J9ujMbx7OFfaa7rRd11iswZ5RzP0zo49jV+hrEhv9DtR3QJTgIJBySCkx5vIB
         bCOeBSCdEshJjFzjKrOmCGp60MdZZOF0d/SdoMapVxJW80q40w2l9hBpdypHBL6AbLRZ
         LCywYyLWDftpGzG5hBJ3/74T8rd0AYh/tHsSS9+BC5whrbw6RSvmCx0zsotVhMfwXnaY
         afE7R/PC6NbgZ3E9sWf1RkRp7WBAIk79u7NKj+89Wxr0IQ3+3qyTPYhHGvi6J+6w77Gr
         kUpw==
X-Gm-Message-State: AOAM530OzizeaQRKXibLMIWrDjXxi7b/8iYNHSZRf1r07OmJsAaKerHB
	47srd8HeS9L81A4Fok11IYI=
X-Google-Smtp-Source: ABdhPJwpCm05txAXofyPiA6010xgHkqMpnSY9nuPECLAs1ZuHQNHevHJpHMFc0XkjGVQx83Qfe7adg==
X-Received: by 2002:a5d:4522:: with SMTP id j2mr19939710wra.212.1633431628797;
        Tue, 05 Oct 2021 04:00:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a285:: with SMTP id s5ls1839059wra.1.gmail; Tue, 05 Oct
 2021 04:00:28 -0700 (PDT)
X-Received: by 2002:adf:9c02:: with SMTP id f2mr20924178wrc.329.1633431627998;
        Tue, 05 Oct 2021 04:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431627; cv=none;
        d=google.com; s=arc-20160816;
        b=mae8ABtn1xVOsBLhRoWc8XOesUr/joOV/ICXwBjgTq/jlDWUb/SlSUWJibunFEZT4K
         lYeMRkPcUFyQFveIoPprLiu8PFf1GbesCUj5A3FHUlW0dpJR4uL6pXc6BKVQEKV91kGr
         eUUTnSB7KPua2Nqd87/WHylGb4sj9GV/4Mmr2wnNmXnuB2NyFhQUqdrS3QS3Iri1KD5B
         1Q4xJskJ8GD0Aw7Dedasye5PMTH7AR8tVPGnzpS4kjZqwyEYQkEM974RNgX+aOlKRcaP
         qBVJvl1rGu3Ewtzl5E0ysVwI1MuspzDDvY1AXKOp5ZnDKzZWbXNmSwNV66PXxKDfnn0Y
         E5Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=DahfAT1Q5cTf5jxzmYjgaD95bFaAqh3xNJSBaROtoZ0=;
        b=iNmvVPCdNATdCUmdFR/envIYlw2OWM8LPD/plD6IiMofSC0iSmuyXKXb8DI/L9daBp
         BjlpGbcrWwEQodaqHODFODxIFv+PwS1/QH9osg9kdh1Rc27VukVHSqxeIa3h6PLjXQEj
         xCa/fHy/zEsk7DwhaFzbj+dj1xdGA6N3+Vy3RxqAel9YEpISMybfZaXywf5yGs1hGvel
         ZeexYiISR8xwCkDzGISMpjVP1iB8hHlwQ99ux0hOnKez9s1L6cCWFy/v9dqEbnyGbiX6
         vSHtPoRd9sus3xTN6JgSAtBT6tO7wCZuuBSaY7ivcw0niXlC7yO2fwe+C9ceIk02ZTQw
         fNDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lZfIqlUU;
       spf=pass (google.com: domain of 3szbcyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SzBcYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d1si660094wrf.1.2021.10.05.04.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3szbcyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r16-20020adfbb10000000b00160958ed8acso3822765wrg.16
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:27 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a1c:ed0a:: with SMTP id l10mr2762058wmh.140.1633431627680;
 Tue, 05 Oct 2021 04:00:27 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:59:01 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-20-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 19/23] x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lZfIqlUU;       spf=pass
 (google.com: domain of 3szbcyqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3SzBcYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

If CONFIG_PARAVIRT_SPINLOCKS=y, queued_spin_unlock() is implemented
using pv_queued_spin_unlock() which is entirely inline asm based. As
such, we do not receive any KCSAN barrier instrumentation via regular
atomic operations.

Add the missing KCSAN barrier instrumentation for the
CONFIG_PARAVIRT_SPINLOCKS case.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/qspinlock.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/include/asm/qspinlock.h b/arch/x86/include/asm/qspinlock.h
index d86ab942219c..d87451df480b 100644
--- a/arch/x86/include/asm/qspinlock.h
+++ b/arch/x86/include/asm/qspinlock.h
@@ -53,6 +53,7 @@ static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
 
 static inline void queued_spin_unlock(struct qspinlock *lock)
 {
+	kcsan_release();
 	pv_queued_spin_unlock(lock);
 }
 
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-20-elver%40google.com.
