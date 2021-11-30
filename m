Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXM5TCGQMGQEOVEJEJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CCD424632E4
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:33 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf13625981wma.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272733; cv=pass;
        d=google.com; s=arc-20160816;
        b=UJcNn7+zgNtnANn7cc4z0LWjfGSJ9I5ut7dunEtgzAPBLJyazbuIRnZtmOnKbk4DuK
         8kUu2y2XydZwnIv7jWKGzdHbGOsueZImcVqqVQPLI0eyENZCM9+7/l2h97Lp5ArloAP6
         6aL836kJWHkRzV+p13o7wFdVLqJ6eWa2OWXnxAdD9XoHuWeA5txxvAZpZv+iUP377wDr
         asYGyj5z1y40gXQYTNa8Y0PHp/m9SqMUW7qAmLoCdQTODNEfT18l9g4IOKd6LyRbwJi8
         jnXSE2FlXke4CNxZVkFWSQOtcmkvTCVUTEabBVPkQtJxZnC5R2CfSzLZp1ytQIL/uAKL
         1drg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=98fFAcQXrrLP6mu90604c42owuVos1nyrB5eG+RFhBA=;
        b=IgU54nCBXl+1hxnH3zenuan0WvyCFMuyeEaNMwC+wcybnn3QRZBwSdxGn4evQ9T6lR
         FjU44E1nT+TEWIa3MheHT+/d6yOpXsusVRrZNObKs+bFH5z9As/p2gbGnf8KEPCNH6wd
         b1GqWvxgFDMC10hUT+oFN3srvJwSPIlDuYgPg7FW/sL2fp4zvpTQFoTl7M4RKbBPd+Lb
         3QKhdkSPn2aB7kjwPboJmD5JIXeLfsPNRtosHI872lYY8occkRWX2W6GBjX0x2vm0GZu
         +1TyLvXnSGrI2pVSy+ChIeUGXGWbrtcFuQ0IdnKFAPALz74YQYPlvFtJ/hBEWyNWw/e5
         Nl2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VRFC3Sd6;
       spf=pass (google.com: domain of 33a6myqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33A6mYQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=98fFAcQXrrLP6mu90604c42owuVos1nyrB5eG+RFhBA=;
        b=UxiydX+PVAsVRw3hBwQU6a5SY7Ancu4vbpe5Gh1CTs9KWFmW7Pf/ttSWiv/IznXNbq
         QczfLTT27WqfOmHjE/K6CLcgUY5VtIEfCj/9h0aQqaNAnMh9wLE/AWbkRHewX8wBel0/
         et7lyttOoxwz85c3riWHXDc6osbOiC5Oenh/R0hDurA6LzV6sVyTtP5ZrucR3EMUkoB0
         FOE0A3V9vBc+1fE+27ONZaXTApxTi7CLrMLwp6oiYjhQFG3Tr6Wl1WhsbvGo0aZii++H
         cao6tXAqIuVnwr97OgeaP7ODJtWgun8xJ7jH4Syoe9sw8cYHmhziaR3Fv3dReiyGM5i+
         InFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=98fFAcQXrrLP6mu90604c42owuVos1nyrB5eG+RFhBA=;
        b=CPronWs3A4TAaftv/jlbqPxn3SLwcLT0t3i4nX0eBukE2Rl197Aa9R35dAbPNUTcep
         HVoZRVhzOylW34K3mF85xFgLQUL1y8BT84M77wjpW3OzzslSTQ+acGx3/hevwE98kknO
         LampS19tYqajpJwlpldafClGP8UsGnN2cHFMKloPSyhPNnm05cp8RurQXGdy4jnA6LIV
         gmAySLrleb9UGyntHxFz9jpu3iQYFqLM/NJstOcKM+vWryIjfkCMVGMuqS1Zwb+G+RG+
         qRuhofIeixUVrTTR9sniGWjbjRqiqBqpvzJFPzWzQJIvmylxVyLQfqtexxQ8M25918gn
         uvCw==
X-Gm-Message-State: AOAM5326lPG5W+KHy5/QpLKVtxLQojlqAWse/+6+IacrKlk41rwkPFCi
	BmL2Oc1tX8j35gUvzBtOYbE=
X-Google-Smtp-Source: ABdhPJyNZItnzxIiFlZ4eTzo5JcKuV3gwwUMJfgPLbZPUjkhhxNlS7PqlzeHpOfDHbub4Rk4VdWegQ==
X-Received: by 2002:adf:d1c2:: with SMTP id b2mr38776991wrd.369.1638272733659;
        Tue, 30 Nov 2021 03:45:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls1233477wmb.3.canary-gmail; Tue,
 30 Nov 2021 03:45:32 -0800 (PST)
X-Received: by 2002:a05:600c:2195:: with SMTP id e21mr4401537wme.187.1638272732751;
        Tue, 30 Nov 2021 03:45:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272732; cv=none;
        d=google.com; s=arc-20160816;
        b=gBxlogFUfJVN0tZKa576aTDyrGXh0S/DhDq8lC+5WFBQx9EfZX0mCkylgpEH4h+RHK
         39+tTFXl/6wzyAk9Xr8GG6BKBxWrWIU5aNyoJY/khRh/ZEK6LVPQEGgTwS9SWzbFrMCK
         UrHje6cyYgrPugA9+kRr0TI+yaMHK0lCioL4ZVW7UTDmdQClx13E/I58TDOP4T5Q+JGY
         gleOiiL/IbYdWRFIdTRF6MHzDvVsVTLfNw02MKLEP7AWMVdZf/E3ZyMGeAM/ELZwSq0K
         m/QHEoYMEzVCeRRp144+7QauziY3YKywCweUj3vYkEkrTNjntdNscjAseu1y1p1IZU8r
         69eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e4DEXl9ENL8f6grIX8Smd5WFfYq3AcFIjaS7u+NEo6I=;
        b=cvTwM4i/bFTfFp30sKjwG5Ct0PTUe6n417VQKRjN4uQoS3rWbiplS/fk4UJu3wVh00
         PVvhZaVghtAN7emoA/WAY2887pECvdm2I4FE9hlz48PZ70Yg4f7nU+3uZmSQyB9/THxh
         KGAEKtIWLiFosMVExImjPB4nRozbgnwJhGZCxTb97RrgIZmYYQ0ZFUqTGhEk+Edor7OG
         JwV8lVYtNIfWUJ0u4g41OjeuyCJzwLNFsutDj1PM5P0F7UyUallaurNgBQldc2qcF2u0
         dOtCODwzzR4woBRTwAftUhAGk+UcpGz7ChDERb9yDA0DhNCFnQbJmS/LK50mF7o7vLCE
         Czqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VRFC3Sd6;
       spf=pass (google.com: domain of 33a6myqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33A6mYQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o19si341696wme.2.2021.11.30.03.45.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 33a6myqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id a3-20020a05640213c300b003e7d12bb925so16763429edx.9
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:32 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a17:907:3f29:: with SMTP id
 hq41mr66294129ejc.216.1638272732309; Tue, 30 Nov 2021 03:45:32 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:20 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-13-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 12/25] kcsan: Ignore GCC 11+ warnings about TSan runtime support
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VRFC3Sd6;       spf=pass
 (google.com: domain of 33a6myqukcaujqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=33A6mYQUKCaUJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

GCC 11 has introduced a new warning option, -Wtsan [1], to warn about
unsupported operations in the TSan runtime. But KCSAN !=3D TSan runtime,
so none of the warnings apply.

[1] https://gcc.gnu.org/onlinedocs/gcc-11.1.0/gcc/Warning-Options.html

Ignore the warnings.

Currently the warning only fires in the test for __atomic_thread_fence():

kernel/kcsan/kcsan_test.c: In function =E2=80=98test_atomic_builtins=E2=80=
=99:
kernel/kcsan/kcsan_test.c:1234:17: warning: =E2=80=98atomic_thread_fence=E2=
=80=99 is not supported with =E2=80=98-fsanitize=3Dthread=E2=80=99 [-Wtsan]
 1234 |                 __atomic_thread_fence(__ATOMIC_SEQ_CST);
      |                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

which exists to ensure the KCSAN runtime keeps supporting the builtin
instrumentation.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/Makefile.kcsan | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 4c7f0d282e42..19f693b68a96 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -13,6 +13,12 @@ kcsan-cflags :=3D -fsanitize=3Dthread -fno-optimize-sibl=
ing-calls \
 	$(call cc-option,$(call cc-param,tsan-compound-read-before-write=3D1),$(c=
all cc-option,$(call cc-param,tsan-instrument-read-before-write=3D1))) \
 	$(call cc-param,tsan-distinguish-volatile=3D1)
=20
+ifdef CONFIG_CC_IS_GCC
+# GCC started warning about operations unsupported by the TSan runtime. Bu=
t
+# KCSAN !=3D TSan, so just ignore these warnings.
+kcsan-cflags +=3D -Wno-tsan
+endif
+
 ifndef CONFIG_KCSAN_WEAK_MEMORY
 kcsan-cflags +=3D $(call cc-option,$(call cc-param,tsan-instrument-func-en=
try-exit=3D0))
 endif
--=20
2.34.0.rc2.393.gf8c9666880-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20211130114433.2580590-13-elver%40google.com.
