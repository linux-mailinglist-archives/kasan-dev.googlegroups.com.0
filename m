Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMEV3CGAMGQEYKRO57Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 648A245566D
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:28 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id f3-20020a5d50c3000000b00183ce1379fesf872820wrt.5
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223088; cv=pass;
        d=google.com; s=arc-20160816;
        b=wevQlxHAm0JLCGLLAWTOVW6jhJ3xEd9vvGtdB0pERflfAfrX8pknbb410mAGCZGHKZ
         U2jYKt1gOj1z7m69UgJvMOHKDF0a4elvYyAa/CM//Jkn8NrdSs9a0m0oYgcHOo5ogood
         WrAnApc2JQpCifB3u3iSMQyz4YH1duHcUL7fpDMrZtY32yH4+ErlsQ9p/VT6XBgSo+l4
         O3ePwU/TdT5pW9zZwK3PVbTBrtcB5ZuS0VWNMlLDOjZVuY/gbkV6DVXo2fuTGv4a7Cja
         gAQRXSRrc6dvZioKkUBMhF97rqhKW5xoIKPOULVsku8QydudXgoYC9mmFVifORKNp9rK
         meCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mKjSqNHP4nkv6ul6HUNrCGh2yxh1IKsQcrzpTfNv0g8=;
        b=HMsTPJTYJLZ/HADqf1gttkx/tSwNG6MtSp/ybKDNFTrEc0vkkdHivlWRKTcH6La/Yw
         jq+WfucrBcO+UHz1d0L7/UCbaew2v09KQzSEeJdAROxXiCYQN1aPgEc3RHWMzmDW+aYm
         kP6gFBeC7bNHy3yBb/EaYJcpTOwzyrwh4Wrts3L1Oq8oJBMcYrxS6wyX8fuR8OseiDOi
         LzpfG8ijaDz4sb1LXKg+bNzv7bOhq6y9zppTIbdwtIUE7tlJwRPz+kA3czqicBPaCHsP
         RR2MzCaur+atdy6sPHbiBQ0+kpEyPyztw7LBe5g+OHiKa9OzmOVBOXLZ8pvBoClDVk6q
         FtXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PYqstpHD;
       spf=pass (google.com: domain of 3rgqwyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3rgqWYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mKjSqNHP4nkv6ul6HUNrCGh2yxh1IKsQcrzpTfNv0g8=;
        b=hP45ztrBlYIQwY4jRO/CCX8sv/1lIxknBax/ld6sClq19l96cAdFBLUJu2bEJschcC
         LlJESD/OPqDqNDWJ79M+yQITmJ7fPeYEA/bfXH8L53Z9XED5u6zRlwPMgxA1mx1SdeeQ
         78Diqxek4Y2y4F3kf1uCksd9cjyC2kEvfBHIT15hy6qopi8cjTQx23WUTK63qQqQ5cCW
         ftU+fJYKUffH4VtNtGGaLXLpQ9zxPLiaws3VO76qrT3L13wa6P6U9vZu0pXoYyefaETk
         GjP5F0IQa/jcWZMtlwtdgP+KyWM9aMQz67XW7yJFEn2zRtDbwANHkYoye12OA1qhrt9d
         le4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mKjSqNHP4nkv6ul6HUNrCGh2yxh1IKsQcrzpTfNv0g8=;
        b=vVDMgGy5Jqce+TKN60oTTJK5TDgQ/PzE5S/HRZEwzeQ2pw0C9ZL4VdgGWCdCUGgsBK
         JiO/5+ya2DC3Ak4m0SdVpDPn98dZ+CRkBycQ7CeD2Pl4vVV8t3xZ37p1pnDxZt2N3R/6
         cVENjQ2VtfoOc9RxPY5JMYMpC2Ck+nEZpX9W7evNEg7nEvfnMlozsCDdWzXnn0nn3xFP
         EiTUQLevrfehgucOr6d1GEqyTsyBJBhf7clXfi2V3fBvm/dnO3V5wNREDtufvFInLSmJ
         jyUzP7dm8r+VXesnM2lFa8rYmY77C6JSkrENqGoqsfZ4RWKQ8qthaY8e260KYv+jKviJ
         WEWQ==
X-Gm-Message-State: AOAM5325NbbxLYhItEapjdF0S9srOgU/sd2v7xWsY/GcUiX3b2c9h/f0
	C0fhricT+4iV+CyJdNB1B3w=
X-Google-Smtp-Source: ABdhPJy0VEiF1GB1qOj5BXowjEbWKtNLd5X5rJFatExHa1gjz6qOXVcLF38D6E+zOW7EbUJkh0Bb0A==
X-Received: by 2002:adf:ec90:: with SMTP id z16mr29659134wrn.247.1637223088177;
        Thu, 18 Nov 2021 00:11:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:23c8:: with SMTP id j191ls1163418wmj.1.gmail; Thu, 18
 Nov 2021 00:11:27 -0800 (PST)
X-Received: by 2002:a1c:19c5:: with SMTP id 188mr7835205wmz.145.1637223087230;
        Thu, 18 Nov 2021 00:11:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223087; cv=none;
        d=google.com; s=arc-20160816;
        b=PIIj/3WRysAmKcC8Vb9s7dlfUijzjPTindXnsSmhdnZ9dzc93QbwmzY5wO6Jb8zrhX
         J5JGpDOucxouOuWteJ8a7ob6LUZFUaBdgOjUUhXf5y0HKJVkHz/hQChISpkTm/rVKXwH
         WmNVK+6Lh8g61kf7AJ+zsvcSZjfycZ35J58Lz8NqgPJuenyu01SiF3IbW1d6IKjIff3X
         eLHOkwTQm2SmR4e5Yrqc5w+mjQq/hBT/QAU91Ry/GJeZg9liOjyQtAQipbDC+Vj136b2
         2iCyUpHEVaDpITaL+yMrIbR1qZWTG9Y6eELwH7Fitpj88bRIUafdqhk4givijYgzR2Wk
         S5NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:from:subject:references
         :mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e4DEXl9ENL8f6grIX8Smd5WFfYq3AcFIjaS7u+NEo6I=;
        b=s40bgGWZdNW3hGZspWdJOtRCa1ZGIm73S3l/77AJndMPKo1XqJwbFFklPA4GB45lUV
         pwMQftw3Z+T30o6LtIpjMJFjxEX7u/Gnbz7/deoiY0ylqdYsUpajm/45zdKm4kMnfLga
         7qkmJwpprH5b1fcq1cjQSyzKqBukpjKQfJ0EsiNYifzy1bNMvLwVimtMq82pklphEw34
         Cy9EITg4QQ+NCorzglYx1X++ejYmKv7PCpZvSjvuNjp5EmcU22p8bzebHlvvLd/H38YW
         ubFDG/n6Auzcw5/CioSz37CtkwZCynS/f5h0WUKb+ifPOPRBLQR5vu0YliRywkzc69/G
         oseg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PYqstpHD;
       spf=pass (google.com: domain of 3rgqwyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3rgqWYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c10si548045wmq.4.2021.11.18.00.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rgqwyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id z138-20020a1c7e90000000b003319c5f9164so3986851wmc.7
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:27 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a5d:6902:: with SMTP id t2mr29764583wru.317.1637223086895;
 Thu, 18 Nov 2021 00:11:26 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:16 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-13-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 12/23] kcsan: Ignore GCC 11+ warnings about TSan runtime support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PYqstpHD;       spf=pass
 (google.com: domain of 3rgqwyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3rgqWYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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
kasan-dev/20211118081027.3175699-13-elver%40google.com.
