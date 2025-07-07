Return-Path: <kasan-dev+bncBAABBSNLVXBQMGQEFNLNDXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C99ADAFAAB6
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:18 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2efe2648f13sf1650531fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864777; cv=pass;
        d=google.com; s=arc-20240605;
        b=kej9UYI2P9LtCgzpZdi0tasxTSg+czPMlAjQ6Wh7Env/KD9TUBAaPG4EkIpnAFmTLE
         GQLcQBrHbLv4SUKTmxTdsGRzbR0ucendvdkTrlB9SlUN813nP7A4KwfsVFYJ5QhtiRAW
         LoozjqcERZVOd63Sj6jF1xESLAOJKGBrhoN2x2Omt5Vi2Yym7f08xSLQC1zSBXlAWuSG
         zEMYYwSaLKeJ1AwHABVuSxBit/+gIKkb4CRCEin5v652PwdQT/5CroHrJnCAcFOQWDwJ
         nKuI6ALppZhxxMAVmn+UvPJzVE+1no9QI7nOEwYwIZESRgB9IQrhuBBd4yhi4nf6YDt0
         9+IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=JAC+TCrbeLJIvsJVdZZEoHGfcrYt5OlbAgSggMyyv4I=;
        fh=rJNpSq95ghwljkouxuppIjGEaxIZ5fOtI85pvoEq490=;
        b=BjWqeUxYFjfty0/XhvAFAJqiq27OOnLtv2HlbrnaC7CN1d+Y/3dCFMFLhvPfY7rupV
         Df7JIfPCGTLsCmzoseLjx2gSLhbZsmyNi0CE4erkbrLOtFaeWyOPlGW/gPR5IC7FfV9u
         FgazN/Ettd4gXFdhP7yvUZTtL2AOMzuzkg9h/PoioOU7j1h+GXP39xuEY2msq3zYS5vp
         2+Pgx2yWy7adrpaWx+Lsr61FsJNUs+V/J7u1OFI/BqrnLf131BixTxS9+7kdmpPp64zw
         Q8+TL38YTLr+ICkpvNP3VXcitQyZ3wH+ayJZg7jwnx3pb038z3snrzN0/smfPR+BR5jo
         nk1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rWb0ois3;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864777; x=1752469577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=JAC+TCrbeLJIvsJVdZZEoHGfcrYt5OlbAgSggMyyv4I=;
        b=Tm7JE2HnXlYencURfoBBJGC4kn68Mejm43r3UiwPnqY6ENdL2xQ8VBS3AdOJcSQ5t1
         7s/kXQODuM59C8/1BYePniQonfXPLJnasqGVcUfC48lxIMKLMThAt5KPBjLhOSzMT+eo
         YKlPck1KiRhziydC3TibyqBQXHWm8YA4OeSKp7+lL4meE4Zd2k1hAiCir1Tpc6Ppc9Mm
         7aGrWsuxzphfSIw0e4sg/BpcsrxtSH+1cuOk3NfkwM035+jKDmhXsf7EU2+KdvVUjI4N
         98XRDpMZ4PQF7SohFlT0Nuo4dGshjMRbXREf2tYaAPWNe6gFmlAOXnQEid+KgrkwxxFC
         lRaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864777; x=1752469577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JAC+TCrbeLJIvsJVdZZEoHGfcrYt5OlbAgSggMyyv4I=;
        b=cA+YtZILpNBB8hSm4dZmQOhk0s9KyHyKQoCLaH64Q7UrltezQFFgVqnG416W7W8zyV
         +lY4k4XXVjCpFpzgAs96riDy37aRFmo3uu3jHPtgpfLPMcG2dp8Wm7tIox5Vjbu9/Laq
         /XDTDryRaHJpytBuPR8fbogXyMBW961E/+ud9dOlAcCYVQ8auvjnyM0j1iMa0vIkZlh3
         a9KrWAUFWJP5mvOTguEdh2vclyMsm62ykLnmk7+FWgj1q41cgl8PV+4j6+I2a8RDuvMa
         tH0y1lDhaMeziZtbOp1lb8aQ2AVq2zKXxF6p36v5HhCuvpJ2m2g7k0M8DgpefcF7dcnt
         KWNQ==
X-Forwarded-Encrypted: i=2; AJvYcCU4v5V37xtS810/MjdyOj0QePdMg4f9Y4+MfvcarXUvItKray3qoevntGevAvNI9GHrPe0xCQ==@lfdr.de
X-Gm-Message-State: AOJu0YzabDMhLwihjECWvPRe9V0fDULJjc6UA8Fb6pruHBIe2GXwja0g
	lUo/3bvC46rM2WgO8bR78n6ID67MLW6Piy90JU7cNKAC0gk5VHwdVHZ4
X-Google-Smtp-Source: AGHT+IEcO89V/L1hPyh/33AmgL2KgKnyUp9IoJsr/xBrVm3q6JWi1vK9vv5e+vkrzGues7qpSnaIlQ==
X-Received: by 2002:a05:6871:b2c:b0:2b8:2f9c:d513 with SMTP id 586e51a60fabf-2f791fa6bcdmr8457651fac.19.1751864777231;
        Sun, 06 Jul 2025 22:06:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduqMnJ8KlKm5P3pXGEpXVmCMyuDjXMIw+oyCbkDUGYOg==
Received: by 2002:a05:6870:85cd:b0:2d5:b2c1:db0b with SMTP id
 586e51a60fabf-2f79b6ea77cls779244fac.2.-pod-prod-06-us; Sun, 06 Jul 2025
 22:06:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWi9VAvNkCgM4/1pcZLuYCgzAL671pERlCbxs7X7+41se4TNoYvXzJqiI1Jx+IuxH4MyJ2b64PVdx4=@googlegroups.com
X-Received: by 2002:a05:6870:9a13:b0:2d9:3868:b324 with SMTP id 586e51a60fabf-2f791fa8177mr8627297fac.23.1751864776421;
        Sun, 06 Jul 2025 22:06:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864776; cv=none;
        d=google.com; s=arc-20240605;
        b=k2cYVo228y0f0nxy822979+eTSe10TswzxRvCZrnlsyWqQY1KkKiQX/JzrkLrHdm3t
         8u6c5rvZ8a+q+6D6WfQTr115X7pFzkCTlTmB5AzJC+4r5VosQsOhnwbosvPukyJPjVhh
         Jx9GzMv9/vzpc6iWdE7tPGz57fbwQbbyxyi8F8QQV3zOm/FbLzp7gHbEZATOHFK2if1U
         4Tbu/oPZSVSaCfo0Gsqt9vbAsLLZGzX7apoNQ9oNef/+2NFErpwOeSOYPig2OET4PMCb
         vlry1PAkB6dTSNZYN2AiLzqD72XivfcJxIw/Hh22CM2M62nm3HCnAm/9cQdODUDdvlhO
         C8hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y7DX2kJVO/vk3KYcewzTeBS39iUuqSt+iqHTtTc3YaU=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=WPXNRBZeIBAQFUNfEejaJKeWHereJh6iPF7ToHzn7MNV3sGNuzPI5cxC1h9ozS9X8G
         CQHWy5PUrisR8FnXEsf/JJ5Yh0LJycFnmxjgCxg5TWlwDrmqgPOcvjr+VEbKvGSbhCbO
         ceDyHmhASXVM9Qo3m7+EPLRcEAxb7UGLmItremfWg2IhV8C2EdFgbfkDHnlU4UyGdIcR
         0t0Vr+16O+xeQu6XuHMz4RAODcS1HaSBkIIj5Oe8MkbOhaqElKhRXjpgVnURPFf0aEJx
         eIyUp20H7pwUOia9jEcKQNoLpyvJT8ehZ3BzuQxtXaQjhqrA9yLBjjNjPuW6Iz6JC2VG
         RYRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rWb0ois3;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2f78fe32307si337137fac.1.2025.07.06.22.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C764946157;
	Mon,  7 Jul 2025 05:06:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CC2AEC4CEF9;
	Mon,  7 Jul 2025 05:06:14 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:13 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v3 4/7] array_size.h: Add ENDOF()
Message-ID: <d8bd0e1d308bc4344240f66c82a724dd67474467.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rWb0ois3;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

This macro is useful to calculate the second argument to seprintf(),
avoiding off-by-one bugs.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/array_size.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/include/linux/array_size.h b/include/linux/array_size.h
index 06d7d83196ca..781bdb70d939 100644
--- a/include/linux/array_size.h
+++ b/include/linux/array_size.h
@@ -10,4 +10,10 @@
  */
 #define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
 
+/**
+ * ENDOF - get a pointer to one past the last element in array @a
+ * @a: array
+ */
+#define ENDOF(a)  (a + ARRAY_SIZE(a))
+
 #endif  /* _LINUX_ARRAY_SIZE_H */
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d8bd0e1d308bc4344240f66c82a724dd67474467.1751862634.git.alx%40kernel.org.
