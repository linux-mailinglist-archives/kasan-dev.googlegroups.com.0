Return-Path: <kasan-dev+bncBCMIFTP47IJBBO4V5CXQMGQEP5WHOTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A698806FE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:25 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-29f6765954asf2848860a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885563; cv=pass;
        d=google.com; s=arc-20160816;
        b=oDQysP4GQ8DpQbLqFQaJ1pgNJe/rkjXWgN0Ege3gA8s/5iPkerlU1T0X1UD+zaEvt4
         DtNNxhNmQcy6D+tLdgD5Dc8WohHRuGFp42a12bgIMxsO/sBoYpIl4+bafr7Kw1cTQVo5
         zh+BjGDYyE9jcFSlzENBDqbtKiqebhu2Jvmn0NMs5B38s70jev5HUxxDP/uQI1+fbVxR
         kLXGN5oPA2g3T75VNAvoNfcApJoLwmV6SvtfYEBVHrpVcu0o+ZqBU8fjURKcOYnu6dyI
         qhSaUJ1LggU6WHsf34o2eAUvnat3lECEB958TJUXCUT/RUFIu6OA27ytD14dEwitBhwP
         lJvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=6qFE3V/y4XHrmYE56lnXk0Qea72LEZNqyBHQV3hLxU4=;
        fh=5g/gx07thPsjFqRgZIxA5lv9voIxZNQCbcoIqnCwq1w=;
        b=hAZbzKWaSChirCoJ4ERXLazU0rrUg2XAdjmaW+qcmnQ/x1F776g46HITaa6hSRO9s0
         o1qrbd1tKj/vAD4dD3CFv/3RtMLEdHFNKPA5h3nUlvU1l2bDcSJ5O5ysUb8543IW3j3C
         tvNS6yvRyxrsCiabBOlOsqvyz3Xtru3DSO5kR9OMzk5+JYI5c2qrdzm7kYzdY+VzgkUp
         GVV1uQppYYragy+tVq3DmESQSG9vmYNv5TrLFX3VNz0aZUUePgooSqBesh6m1ZkKaurb
         IM4NLnbjl7HrWJhO2pT+cE8LSRSI0YbeAWU9D58ktbEsNWipgsPlPmGWNFftLUpgWoQw
         Do4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=NujekRdm;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885563; x=1711490363; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6qFE3V/y4XHrmYE56lnXk0Qea72LEZNqyBHQV3hLxU4=;
        b=q8M87/L42jYuoQAwmQsTtGQXP9fZLe7yEZjLgwB6vJvDUThQCFbLPun1Q2fsBTfh4/
         WdJzaJQaLHRuBOlLd7MvR9ogqsJaZ5ttpWJ4XEeDSu1COWsR3M6BGMpdqAZDj+GoaT4F
         T1HX8hEgR3/HveOO6T1MOK4HhPc1kANXz2aiB347IvEzZKuvNqT58DSVB2ZukBFu6h5P
         zs/2LOMo018ltfoNEDxm1UWUylRbze72U7SV5vA2ghnZpQd1vB1qaabma5VEEMLXcAsZ
         pzXzVBMKPQ/3pAhGo8rwszuee8CUSbejGLBEfNRIYcMWnJ6mlrpwhoKk7+NhK2WODS/i
         jUkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885563; x=1711490363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6qFE3V/y4XHrmYE56lnXk0Qea72LEZNqyBHQV3hLxU4=;
        b=m5225NX+A4Ngo7BPUDXIs+fZ30chV1UcGLBcsdvw6CLYXFLsy+U6OAWy7qmKEbFMAo
         A8chhG/DSoY0I/tNKMCOqQrBj/sQ0jHK9m4f3MFZcDKlJFObuo9sHqVsPuV6AGMxwNJk
         ojT1yCpm5YEAuOHC8P1EA6nqHL4XWXKsY4IyqAERpeWyHKcjEwz+eVH3XNCzkIcqUlCX
         d0nHcNvMLq9bQYrAVjJmtFcCiHlTa8ju1PiuGoTcJHtCozj9OIbvwMIbTIoYbNjcnUEF
         DBx2v4nPpPj7cpz0KyENhTOsFwPNIS2XnJBobjlhYEKwYiQXbd4BcrxGTNWtiDq5t+AO
         E+9Q==
X-Forwarded-Encrypted: i=2; AJvYcCUPDGyKJmL9MEjxM0Bd1P2d6F2ZmPYJ6Pq6zu1qbnO39N+2az/PQA7o/84OWkd7CxkoO88ZX44HyEBDSrJO7eN5+N3qNL6elA==
X-Gm-Message-State: AOJu0Yz7eB7qs6Sam2tFIYSh7XAvABZ/LQGpaEgWh5Al0f/GmANOPwkg
	DkGg1FqRQbw51ZSNaLIC/Pl02/HJN5SZEFFEBL4F9Kp/l/AqKTTA
X-Google-Smtp-Source: AGHT+IFdRftpiQ2wi/ZAGfenEUQYkyraDJERYXUi0kBfha75zOKuC8wmuU4a/fLc+6LDYgclBppYAA==
X-Received: by 2002:a17:90a:d503:b0:29d:f1e9:a9d2 with SMTP id t3-20020a17090ad50300b0029df1e9a9d2mr10642596pju.49.1710885563710;
        Tue, 19 Mar 2024 14:59:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d916:b0:29c:77f6:bd96 with SMTP id
 c22-20020a17090ad91600b0029c77f6bd96ls2954622pjv.1.-pod-prod-05-us; Tue, 19
 Mar 2024 14:59:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUORBZOIeujkM8HEWjeGqjBfgk11asnWvnN8W0U6h0/S9SeZg/BnCWJS0BLO3tVRY/Pk0Vbg7Rf9+RsyaQX74XZ0UXxRqF15WCTg==
X-Received: by 2002:a17:90a:d503:b0:29d:f1e9:a9d2 with SMTP id t3-20020a17090ad50300b0029df1e9a9d2mr10642571pju.49.1710885562558;
        Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885562; cv=none;
        d=google.com; s=arc-20160816;
        b=OI74f9WxskQso6fifkmLqO8Sku985gE00WNv3FGZDGJNJ3Ocyt46q+1H1J5JvdGk9U
         9UKQtSUvWC0OkD1t7Fy+NghQqPAcqJ6B/mBmXdzt0Gv01/0+tEbfkNe29pLvRGLnUzfK
         e7iW14gXoUDHcYf4iMkQTJBgHdF/lKQ7OXPDwg9M1mShUoSK9Nnra4hkxrUejqzauBmJ
         dPs3Tu5ZXoKkl+2jIR/RYc6KDzs8YAo7jLww3VKmfh89sUNh2b+mlGMTLHnjKqayNyqK
         9+zUvatXOJ4Z4XwE8SJxYAWdyi/hODSO01Qmcq1pcV5mO9BmTr8z6/o4cKPJGb+UK8RL
         nT1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ciVO7+10eZV72+E/ORaPRZFjospVEi/8CuyB7rGS1wk=;
        fh=KUFV0mVujp5VHN50fu74NzWziEuC+vGxHaSUf1BPMKA=;
        b=DZ1MfNGeA970N9isfVaGguTNvks3OaWIlGCXsknY5zIo4Ehyuyl0K0w/4oYC/V5bhI
         O2pRtErbLusiZ0e+9gx7yW6itRbeNTOGrp65r0ceTET7q6mQ1YavOx7ztX3SbBV260be
         eY8Uw0nfV9gYc2ipl0R1Gt+lF5lLq7LyB/MBuyU9FD9kFknC8saCdWteZl5ReP7hKjPX
         mcrDmt5E2JFpS7BvkE2+p+XDMQb8GEXOvuXUtiWBZz762zrO5V6Eh2n0rBQDs1XqQQTz
         pMmHZvHStnY2AWHDJDcoS3d+N0pMkMKN7hrZZxvhkPmEnQkvWcrQyr1kgtv0K0MasWSm
         LvYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=NujekRdm;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id z15-20020a17090ad78f00b0029bf3ffa9aesi7891pju.1.2024.03.19.14.59.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-6e6f6d782e4so4000994b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWjUogTTpdGORcqU3tIDsHbJRijCH/FZKAxPbUjgubk5FqJZwL3/E5KJZfyPiCFv2Rshau914cYpzxrQYYIBsxvZAy4/NGulpvJNw==
X-Received: by 2002:a05:6a00:721c:b0:6e6:fcd4:4f44 with SMTP id lk28-20020a056a00721c00b006e6fcd44f44mr11479878pfb.16.1710885561953;
        Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:21 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Paul Walmsley <paul.walmsley@sifive.com>
Subject: [RFC PATCH 4/9] riscv: Define is_compat_thread()
Date: Tue, 19 Mar 2024 14:58:30 -0700
Message-ID: <20240319215915.832127-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=NujekRdm;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

This allows checking if some thread other than current is 32-bit.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/include/asm/compat.h | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/arch/riscv/include/asm/compat.h b/arch/riscv/include/asm/compat.h
index 2ac955b51148..233c439c12d7 100644
--- a/arch/riscv/include/asm/compat.h
+++ b/arch/riscv/include/asm/compat.h
@@ -12,11 +12,18 @@
 #include <linux/sched/task_stack.h>
 #include <asm-generic/compat.h>
 
+#ifdef CONFIG_COMPAT
+
 static inline int is_compat_task(void)
 {
 	return test_thread_flag(TIF_32BIT);
 }
 
+static inline int is_compat_thread(struct thread_info *thread)
+{
+	return test_ti_thread_flag(thread, TIF_32BIT);
+}
+
 struct compat_user_regs_struct {
 	compat_ulong_t pc;
 	compat_ulong_t ra;
@@ -126,4 +133,13 @@ static inline void cregs_to_regs(struct compat_user_regs_struct *cregs,
 	regs->t6	= (unsigned long) cregs->t6;
 };
 
+#else
+
+static inline int is_compat_thread(struct thread_info *thread)
+{
+	return 0;
+}
+
+#endif
+
 #endif /* __ASM_COMPAT_H */
-- 
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-5-samuel.holland%40sifive.com.
