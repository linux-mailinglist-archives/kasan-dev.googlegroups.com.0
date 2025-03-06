Return-Path: <kasan-dev+bncBAABBJU7VC7AMGQENSY3JBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FB4EA55869
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Mar 2025 22:12:08 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5493a71ae78sf768500e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 13:12:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741295528; cv=pass;
        d=google.com; s=arc-20240605;
        b=dZOs0ZkGuC1eg94khiP2RKxTaKGvQxI/HnSVlVfF9DGAC0NUnEYn+i0v5LRxmKnKLj
         kNQAP28G/y7gHjDQTuiMRyKyAbPgitH5C6rvj61nzrKJrE4kJcTkoTMlP/UOeD9sTMfO
         aEXz7Ozq4SF3dv1d2EnKSi/0nAw7RuuwX6jhwIDJF4Urs4t7BBe994weHMigLnFh7PMM
         tB9BDtoOWWJhzGKFMRTHs0ZmRU7zvbq0H75FFYZTV+/R942XZor9km31eYebFXALrKzy
         HMn1ADlm9MBnHZJ4n1v/keJ+is9oxfpBD7QjPoVsBnulWS0RPfssoSbHOip7qXVWSAGg
         1J6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=mYtxILv6wxqV2XJkBIN9Spkrvnn3Wr5uMAV2sMrxytw=;
        fh=ddEMA+TW39lG580QaSYtyxTah/G8goNeJdao+6GF6hY=;
        b=LwZ2ndgUapCyYmTfxq3+CYqLaMcsT16549uJB9NkIi/AIxNiKm7YIIGFOAqbFgXGFw
         lwuY4aTeSXFe8hoeaUUrY80GFNyLjw7Ioq5X4oHKSrPm12bhzwiNn/AZvZbkYZE5Umv4
         D0bdREieQEmFU5e60A9pKaH9oTSVI/oAHvG6mfY7vEvpZ11GFQEluMx43tRxcNdFMmiX
         2lScZQxkP9sBi8QVtPH7c6gVXtXm17oPQkHGskq42zX/fjW6DSD57dy1HqJQJGuaJ1x9
         W1nh5XQb88lZHsmF+Hhe2YE8W2/iu2gB1J9Deh8ISXuToy48Vw8LPjFcz1UZBTtFaYU+
         p9QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=XVN4ljCe;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 95.215.58.177 as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741295528; x=1741900328; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mYtxILv6wxqV2XJkBIN9Spkrvnn3Wr5uMAV2sMrxytw=;
        b=s9cvIV/oWC5Av/RgccC9YTbUFm2PU6i+Lh6x4DdWwqT/+b9nmLmfmloDOSjnN2Mk1q
         bDihc8/5Q0jkzu4iEeAm+yX/ieU0aKZ2udiP0av2qg3Brcbia5JxbefomPOhOFyGUx+Z
         /1h3GTLaLrr9LEQZIQu27enQsaceH4PWSwRFmY7/sk6bt4if9fQhb0Kk1GGBvsaQ7M2S
         8pD46BT9kLs/vt14bxzZeXeFAAIiCOmlr3DdTRIjIpD7q+M6KyV4xHPwuq7u5MyWR00e
         s2IrZJbc/kCzJB+2AL6Yp/3d/pv3S/dfk+P45eBk/WTLkAN74vMD5vq+ISkLCeSAjQ5X
         nJbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741295528; x=1741900328;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mYtxILv6wxqV2XJkBIN9Spkrvnn3Wr5uMAV2sMrxytw=;
        b=remE35WIC69m1nM009CjFff0AzV7QjTIS16q9wXJipY++x2N9oUGMSrsMEU/sv9dDQ
         Cwkcm+1uomtPKnZj7tis1yL0F9PhIaMUuxHt3pxP4F4BaoZu48QEhYC0ezugIt2RUuyM
         Iaug1VQuIxpmVoanHriZHXqnLZrtUsRMTyDPoIGIJGFSUaOq6GKBGSfDy0bGXkvMj6fc
         QdBzHNYpFFgDGeP/7Fx36u6ATMOqM2MplW4tXk7DXmWpMIColtw75NHOV1qSsUPGbQdh
         o/UcdujIGtAe6jJJYjhKB1L1msIC1YCRulUX0KKx6YhApDZPYstghdAmXUdv2phkK8Hi
         j5ZA==
X-Forwarded-Encrypted: i=2; AJvYcCUB7cIqgYk9knjdN0aTtPagYcKHi0xJkIOC8m7UvWmPrKgfvUke3IvyPMV7SsKX1lH0S6mqCg==@lfdr.de
X-Gm-Message-State: AOJu0YwzEeQR5gCcib33N4qqZkF4xEX2aPXjMg69F2TIzK6CFFC/T/Hf
	0gORgqQBsACyKsSl+IfghwKX6qLdvWVTPWPpRKeWcp8n3TPVCJyt
X-Google-Smtp-Source: AGHT+IGuV9P26Pvvo+UkrdpFt/sE67xisIAENhvZ3NAYPUc/DxM0LLCtPe78NxabaQDJ29Apl1SCVw==
X-Received: by 2002:a05:6512:130b:b0:549:5dcf:a5b with SMTP id 2adb3069b0e04-54984b82808mr1741720e87.4.1741295526877;
        Thu, 06 Mar 2025 13:12:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHiqTEOxXlcm707u5HyRroTrIkY8i66MCcjKJ00nAmjGg==
Received: by 2002:a19:e003:0:b0:549:5630:2816 with SMTP id 2adb3069b0e04-54984e69493ls51995e87.2.-pod-prod-00-eu;
 Thu, 06 Mar 2025 13:12:03 -0800 (PST)
X-Received: by 2002:a2e:ad91:0:b0:30b:a76b:e4ab with SMTP id 38308e7fff4ca-30be33eefe0mr23269001fa.8.1741295523449;
        Thu, 06 Mar 2025 13:12:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741295523; cv=none;
        d=google.com; s=arc-20240605;
        b=FV3a7WN1dhwn1K9b35UJr9G+PpWLBJv0pIscjYM4yfjWdYjYStlHRHELQO1YkodLJ9
         ra69PBnfcJA/pOm2tEoGwD7S9jpT8KUcY7L3kbT9fHc4wFYWd3IF8W/F8Y6DryjUefxp
         5rtuizRpOH92d67U8Qxlx6cgKC6fq53Xi8IZgePEG0DfOAvNbxhgZ0zXrzbi+pjmiwS+
         JYzlC5jVMQJefbzVYAqWPRnI//Y1C21NVtuMgz2MFHFc0Qi0iAdxlRSUCZ/O5zSRu2VN
         Twn5HigoXzFP/Z941fCChPVdk8sIQ8yJnbGbNbmn5neuSmfqmgtDz7uDcl3f3jlZAr5P
         9j1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=y3UeIRikRnYRQC1pPCbxniJMgfci1KvvEP9uumjgL+U=;
        fh=YiO2AZ4Hr/NmsMLhKliEoOMq2xLQ0No97Q3xyFYvel4=;
        b=a8Sf1eDAx5lHObHJYsEuZHeRXbrHIOKmcqtt4Xrg+hQ7DR8OGjvLt5J+z8olYKOCfb
         QwTzFPc/PcPXZmRCbngzAxYJzXyBAkwOuee1k6zUxenQXrYK7cuq8h7UGZZGrMKUaEfa
         RoqDYiGNBvdR8PQ3BrynZOQCkS8qpy59gcgDRz6f/PJZiApYnXkFYtSLX40Yw9nea1AR
         dhzer2Hb5WYevKYnNjnxBcAOc8XrGzVUOH31CTwpNa7ZabT0uZJUxvfiJx/bb3r4oppk
         RY/cFUQTXOYGQFmWYYjZDo4h3Y9EO+n68nOvQij1UfsK+n9nrhFTm9iT6HMy/8QdTuK0
         7+oA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@iencinas.com header.s=key1 header.b=XVN4ljCe;
       spf=pass (google.com: domain of ignacio@iencinas.com designates 95.215.58.177 as permitted sender) smtp.mailfrom=ignacio@iencinas.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [95.215.58.177])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30bf4f9fe1bsi34951fa.6.2025.03.06.13.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 13:12:03 -0800 (PST)
Received-SPF: pass (google.com: domain of ignacio@iencinas.com designates 95.215.58.177 as permitted sender) client-ip=95.215.58.177;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "'Ignacio Encinas' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 06 Mar 2025 22:11:45 +0100
Subject: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data Races"
 URL in kcsan.rst
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250306-fix-plain-access-url-v1-1-9c653800f9e0@iencinas.com>
X-B4-Tracking: v=1; b=H4sIAJAPymcC/x2MSQqAMAwAv1JyNlD36lfEQ6hRA1KlQRHEv1s8D
 szMA8pRWKE3D0S+RGUPCfLMgF8pLIwyJYbCFrUtbYOz3HhsJAHJe1bFM27oiF2V80xV20FKj8j
 J+7fD+L4fi0brDmYAAAA=
X-Change-ID: 20250306-fix-plain-access-url-8ae841efa479
To: linux-kernel-mentees@lists.linux.dev, skhan@linuxfoundation.org, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Jonathan Corbet <corbet@lwn.net>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
 Ignacio Encinas <ignacio@iencinas.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: ignacio@iencinas.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@iencinas.com header.s=key1 header.b=XVN4ljCe;       spf=pass
 (google.com: domain of ignacio@iencinas.com designates 95.215.58.177 as
 permitted sender) smtp.mailfrom=ignacio@iencinas.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=iencinas.com
X-Original-From: Ignacio Encinas <ignacio@iencinas.com>
Reply-To: Ignacio Encinas <ignacio@iencinas.com>
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

Make the URL point to the "Plain Accesses and Data Races" section again
and prevent it from becoming stale by adding a commit id to it.

Signed-off-by: Ignacio Encinas <ignacio@iencinas.com>
---
I noticed this while reviewing the documentation.

The "fix" isn't perfect as the link might become stale because it points
to a fixed commit. Alternatively, we could lose the line number
altogether.
---
 Documentation/dev-tools/kcsan.rst | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index d81c42d1063eab5db0cba1786de287406ca3ebe7..8575178aa87f1402d777af516f5c0e2fc8a3379d 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -203,7 +203,7 @@ they happen concurrently in different threads, and at least one of them is a
 least one is a write. For a more thorough discussion and definition, see `"Plain
 Accesses and Data Races" in the LKMM`_.
 
-.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1922
+.. _"Plain Accesses and Data Races" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt?id=8f6629c004b193d23612641c3607e785819e97ab#n2164
 
 Relationship with the Linux-Kernel Memory Consistency Model (LKMM)
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

---
base-commit: 19b100b0116d703b9529f7bbbf797428de51816a
change-id: 20250306-fix-plain-access-url-8ae841efa479

Best regards,
-- 
Ignacio Encinas <ignacio@iencinas.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250306-fix-plain-access-url-v1-1-9c653800f9e0%40iencinas.com.
