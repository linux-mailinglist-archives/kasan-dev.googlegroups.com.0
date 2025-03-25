Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB2VGRO7QMGQE55LIXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9750FA705E7
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 17:01:48 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-54996792145sf2615539e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 09:01:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742918508; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+u6wiEjubzGPumRCgpPAnKJDdAwWBNCLTPISWJNWK+Q6aIuApKPj2AKdALD3s+I69
         ZZ1pIpyOOT97MUaHcL81uolBLM1wkKTCKlekpOOsICirbcmrxTYX4EWdNqe/kz6PTGYI
         /47jNdDWY2ybZV67KYk9Pq5fI21iUvO+QIT0HOGlEoCBwLuzGjAhn0ro+Jq0G4HYNrOZ
         tMh4RtCpVKD2XZFFL01Hkej77OrozF5Yf0mYJcJX6MjzTGzEriSBUYL2xUU7ocSFOpl2
         4iOscRjX/jU/S5XmzFjNHBLSh4XwNvJKPQBApmw+x2frCIFHyOLSd4Y1C4HMJ1Lymxpj
         KGvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=VHJI4jc2aNFgo8NxKP9CcVZxk3LKtiWv4g8UscaggGA=;
        fh=hXE8o223j2XkpwvPXDSwhKijRMKtfiew6W4CNj1xVbc=;
        b=AkhyHze0C6sYKuFLWbVyE5vmhYyxbkWxzpIEQciFn0wCgEaIO37sXvePbh17FowHXZ
         T3ls23crBBHnaUrhoEDkmPV7/wZ19VXdepB7wwOa2wMZQ4fwkdfV30j8XSCxty+IpA7b
         7yA63MkouA2+6U5IdeA/EFg0h7jRBzvGMtFcACp9+ShnuE9KdD4BpRgouYhqeVl2pncU
         oFGdOP1aN5F78k5Pql0bHEAZNns+LsO69FEJkOv6l2DZmtAYOgMpVLrzanEBi2vlvcQ6
         Ttjd0yS3qIrOHgIgfiZHyrxwUpegbnEXGgpYHvdF7UPRZcVF04Ue0ITR6BaMtpNYaU+S
         /VZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Uuvr6AP6;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742918508; x=1743523308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VHJI4jc2aNFgo8NxKP9CcVZxk3LKtiWv4g8UscaggGA=;
        b=NjdlCIorhfwztITjlDE+D5Xre/ix7zBhx9bmJiJHnpZ6KySbZGIYhufKv+aaxPl4uw
         c6fLF8dLPc+81hoSBq2CxpUn6TQB211dHdogXTFGTnr5GaCOcjg+s/VtPIUzkgjAFxPw
         E0Q6j2zcPOZ745MFWBJNi02C+xA6mmzT4YHYCWkVcOokG5mcZrDuO49Tsxm2M5z9eBF0
         dDbRzQbsbcqX2Y4vY3g8otK4BH/ZExJfcCFXIgfoYGcAX0IEBVnhzTECL4ux2QUtdXpv
         DiteONesUbb3qWu67x0cs7KSC6xxYzXCICE8oLyWrzjpEFz5UWT4ulTAno9O6pUEu+5Z
         9iZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742918508; x=1743523308;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=VHJI4jc2aNFgo8NxKP9CcVZxk3LKtiWv4g8UscaggGA=;
        b=mhDotLoH9ltXVG6HeaP+T22lJbepWMSvm+MqN9jHldYXFtIwmBwHClKj910GNUa+L7
         SRsvC/uy9YYhU7FazKBkIQdBxrmus2EXicvDwNnuByIWzH4+eMrQ8zekW6NZs6IiE3FU
         GUONuYPHda3vaqHIwSdgMkrdjBCAGPfExEceZDWWmGLRuQYAuLnl2dziisK+QXkHIA95
         7jXZava/wKNz01m8dxiq2zOKMaomsYPzewXNsOnRBHDhB7r1NHlASi4swc7PC+pTWeHn
         mmYMdi1/lMOwefDbo1GEOguPX+A8Tv7M0CCTPa5G+ZVLrzTerzB33ZG8rH0Kx45vm9Nl
         MNlg==
X-Forwarded-Encrypted: i=2; AJvYcCX0H9whcl5UJrIP1t7WIj+1oYucStil+GP+8j6khwpjWGVDtOYAHD3MOcW+YgAs0Ls4KvrBoQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywq2wh0MeGxdqW8zVww3nL2lMDS5cCdZuLU20EesDwIdVufOyuN
	tqDlqE+sfzrcKsEthLIOYIzxUVp8BARmHuVCKkKETYT8ySm609Sh
X-Google-Smtp-Source: AGHT+IFa6WTed3bUxOhjUcN8q6xG1YT9lTo4WbM+zW+HkouezFLQ7AlafcJjKmQEhd7TfAmVvisnKQ==
X-Received: by 2002:a05:6512:3d21:b0:549:8b24:9894 with SMTP id 2adb3069b0e04-54ad64860dfmr7683745e87.15.1742918506958;
        Tue, 25 Mar 2025 09:01:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIgNkRWWqjeA7bmE+tn3cOv92XtixtufO9LVQNglH/9mQ==
Received: by 2002:a05:6512:2209:b0:54a:f77d:8332 with SMTP id
 2adb3069b0e04-54af77d8516ls184141e87.2.-pod-prod-03-eu; Tue, 25 Mar 2025
 09:01:44 -0700 (PDT)
X-Received: by 2002:a05:6512:3c96:b0:549:5769:6aee with SMTP id 2adb3069b0e04-54ad647991bmr5386402e87.7.1742918503706;
        Tue, 25 Mar 2025 09:01:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742918503; cv=none;
        d=google.com; s=arc-20240605;
        b=TSP5Gxga06xNTkJp2cVl5XUffgg3NWalJHUr4nRXIayqD5EpW0u4OJ3UjbW+G6AEZl
         ToFOEgpA7g4WwQ+nJelT636CR65JhoTzkzUZf7DLAyduQlbfaqf9gOf9Fb5bbJFParXX
         FWxKMEsg6ivaHwpqGbCsNDX6BZkxs9O2S0r5V+JF17t9C8y4t2NBZfEXGYoy5lhAZZ0o
         4XM85ai/BdMYezSeEZyTejh5VAVgQYjqJgksb+3lTKI7b5WHlaN7K/mt6KRqDkUv2l1t
         IXiALbXlgsXey7zkKOrcuJ72DpPv0P5GcSTvSIOGb+JCrW1lbcl9togIomQk4F/4QKC1
         aTNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=rNLrWaHC+F16KWC7Wcys7gq72QWKKTUqdbgRYbG35Hw=;
        fh=YFgvMh8mPjDCOvqlOHG7chtFWQwfWVVQxZFoE+sW5qg=;
        b=B8JFTCdFnTpUWCMwFUi37HflVEsoqhzIN7jkT532mEVAITcEMeLKzf57i7HsqZc3tx
         6udbi49iXQRgVin/iuY22Gv66ovbOAmAcpD3vCVu7MUFRLz+4ny5z8EQ3f4RVskgZdxg
         v2aetZPUpYeq3EXAMwu4NV3JNinirOHBWLMmeLmN1gRXquHLy5dOz32DmCXuf0wZI0Y7
         B0vuA1Q761Ngths8aVoCJZLt6ewZ4XnpCU/Y1YYGXzK8jpFf2z++hITnDa+xKd6supI3
         Uz4YEjaXH9PyzcfcohkOC8eEqp4WiwdFSJ3GCZF/Y17UkH/aDgyWGTHPJT4Udx5b2TOU
         xz0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Uuvr6AP6;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30d7d77dcfesi1965531fa.2.2025.03.25.09.01.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Mar 2025 09:01:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-43cf3192d8bso60625e9.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Mar 2025 09:01:43 -0700 (PDT)
X-Gm-Gg: ASbGncsS9h9WYu9y6Ilnw97OucEFMN3/z+nU+/hBtQSIAzqhZOY2Dz46f346a2qzBrr
	YBpmDoLJxxQC9uHERNaV5aKi8hppznokIg7DEgxPFd0rxVerV1PYhbxlFsztt8kMHlcONNbFD4h
	b2e8vkwHzepS9etUT72qZN1aZV+H/YSSqm28AZJtzVpNljQNCal46ngjRuLh3dnJcabYAEpDJlz
	RR6MWpL5L3A/sz6jrSj8Y+Je7YQ2hFC5TOwkDH2GH4VU4iS92VUlZWiuAVBvwOjqcMh+lAxJVUj
	+GxWXl+Et3/APcBe2QyHk/Qv6Zja/dQaHA==
X-Received: by 2002:a05:600c:1c8d:b0:43b:b106:bb1c with SMTP id 5b1f17b1804b1-43d591c2295mr4838215e9.0.1742918502385;
        Tue, 25 Mar 2025 09:01:42 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:1e00:1328:5257:156e])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-43d43fdeb6esm204516205e9.31.2025.03.25.09.01.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Mar 2025 09:01:41 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 25 Mar 2025 17:01:34 +0100
Subject: [PATCH] rwonce: handle KCSAN like KASAN in read_word_at_a_time()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250325-kcsan-rwonce-v1-1-36b3833a66ae@google.com>
X-B4-Tracking: v=1; b=H4sIAF3T4mcC/x3MQQqAIBBA0avIrBtQw4VdJVrINNYQaChUIN09a
 fkW/zeoXIQrTKpB4Uuq5NRhBgW0h7QxytoNVlunR+vwoBoSljsnYiTvNVsykYKDnpyFozz/bl7
 e9wMgdafTXgAAAA==
X-Change-ID: 20250325-kcsan-rwonce-c990e2c1fca5
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Arnd Bergmann <arnd@arndb.de>
Cc: kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
 linux-kernel@vger.kernel.org, Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1742918498; l=2606;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=O2dKRA9uvJbAtmJ8DU5c5NB3nWRxzGZSCc3fQ+OAJwU=;
 b=pD/K1HEzZBcPmL7dDKYAHw7aJiLQxHybO/JPTsCHTVCbR2lbNDnEkZVIXWh7hZC82JiFHIbka
 JyE20sMYsBeCBqqi9VId3Q0s9Ahg7NAmY7BkecpwJtQZlp2u/OebQm6
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Uuvr6AP6;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::335 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

read_word_at_a_time() is allowed to read out of bounds by straddling the
end of an allocation (and the caller is expected to then mask off
out-of-bounds data). This works as long as the caller guarantees that the
access won't hit a pagefault (either by ensuring that addr is aligned or by
explicitly checking where the next page boundary is).

Such out-of-bounds data could include things like KASAN redzones, adjacent
allocations that are concurrently written to, or simply an adjacent struct
field that is concurrently updated. KCSAN should ignore racy reads of OOB
data that is not actually used, just like KASAN, so (similar to the code
above) change read_word_at_a_time() to use __no_sanitize_or_inline instead
of __no_kasan_or_inline, and explicitly inform KCSAN that we're reading
the first byte.

We do have an instrument_read() helper that calls into both KASAN and
KCSAN, but I'm instead open-coding that here to avoid having to pull the
entire instrumented.h header into rwonce.h.

Also, since this read can be racy by design, we should technically do
READ_ONCE(), so add that.

Fixes: dfd402a4c4ba ("kcsan: Add Kernel Concurrency Sanitizer infrastructure")
Signed-off-by: Jann Horn <jannh@google.com>
---
This is a low-priority fix. I've never actually hit this issue with
upstream KCSAN.
(I only noticed it because I... err... hooked up KASAN to the KCSAN
hooks. Long story.)

I'm not sure if this should go through Arnd's tree (because it's in
rwonce.h) or Marco's (because it's a KCSAN thing).
Going through Marco's tree (after getting an Ack from Arnd) might
work a little better for me, I may or may not have more KCSAN patches
in the future.
---
 include/asm-generic/rwonce.h | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/include/asm-generic/rwonce.h b/include/asm-generic/rwonce.h
index 8d0a6280e982..e9f2b84d2338 100644
--- a/include/asm-generic/rwonce.h
+++ b/include/asm-generic/rwonce.h
@@ -79,11 +79,14 @@ unsigned long __read_once_word_nocheck(const void *addr)
 	(typeof(x))__read_once_word_nocheck(&(x));			\
 })
 
-static __no_kasan_or_inline
+static __no_sanitize_or_inline
 unsigned long read_word_at_a_time(const void *addr)
 {
+	/* open-coded instrument_read(addr, 1) */
 	kasan_check_read(addr, 1);
-	return *(unsigned long *)addr;
+	kcsan_check_read(addr, 1);
+
+	return READ_ONCE(*(unsigned long *)addr);
 }
 
 #endif /* __ASSEMBLY__ */

---
base-commit: 2df0c02dab829dd89360d98a8a1abaa026ef5798
change-id: 20250325-kcsan-rwonce-c990e2c1fca5

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250325-kcsan-rwonce-v1-1-36b3833a66ae%40google.com.
