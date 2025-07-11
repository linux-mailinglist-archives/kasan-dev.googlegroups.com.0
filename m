Return-Path: <kasan-dev+bncBAABB2W6YHBQMGQE6AWRYNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 64132B01103
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:57:00 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2e90e7f170esf1647603fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:57:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199019; cv=pass;
        d=google.com; s=arc-20240605;
        b=iLIKs/RT3kNWkxQGUDyUmSjLRE8TenprSX/xUboCJUtDFQN8gtQ03VcUNXETFsWG+x
         ogcNMt1k91PIrme7DwKqs8578ffPqByeDr+p8ALmiyDegI6pviNLoxY2f7npCWzXSca8
         L1dKhwmOsKMuW3Ou1qOxNPp4QBrWYSNjB1Ve6xFHvZdbkmk+ZmnLwOUy2UFal74KQr+f
         4Zpgk1iDvr4qA/mxYDHMI0IprpB4+EUp0JtGKuWxoo0jShjmnu51kNrFbxe4aA5WvKDC
         M2JyzCkMVmgafbarXzw24AMOSO5pnr4CtljHtEh0/t7dYR2Y0PxmZhmpUXPWBvBklPXt
         DvLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=q0+bcK2/AzzMDX2a7oj/fjxqiGEImPwx1w1Rqa/aVtQ=;
        fh=57jXt7JGztgpbAhXVCeTClnmTbRI0TzITLLliQf46Q4=;
        b=cr6HuGfI25E/ftqF/enmxt8ZYJEkOnnLKxnmUm/D1oSnNziOh9FZ8bjiTzUIQA/PQE
         Ofec70j4YU7P6ZAA7twuKZcl2cJL4giY5ohPsdH05LzvkVGHVtnTlzFxxJDWAL9Qjt12
         IqjYebSqfRoMMKDG9l/QDq0Hw7OkWhcQxN0A6UmErDQIncwSkdE5dDgpTGOGikT0hBMr
         aZgTVfhr+qFegX8XS0QLnVAUyoZCnqN/gY/PIC/0MDi2qv9OiR+GVdkwTFx61/QJRglD
         sBiV+PBXyQJA2CuXwYJvpPc1b6+jL5Oq1dmh1Y4BOmJQ5bFXCqFjUUFKD4woYMUgD0+L
         uddA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ts7eRZFX;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199019; x=1752803819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=q0+bcK2/AzzMDX2a7oj/fjxqiGEImPwx1w1Rqa/aVtQ=;
        b=O5hXBKZoxkh4/d4F6SpFfWYxDpR31SYdVdA7F2u74bekdKqMC3uVx0jztpxKiuEqes
         GdryO95WVmJIFmwy39Gqi7NbOVbcqb3j0D1UWIdgPN8aTl/Dvt38WSUNwmCPdgoCX3/J
         x4jFemfuMEZzxbzD3KQoeeYJ6TSK+Y4M8t5HHDkkW1Xc/Z5jzsaGtSrwNCnIcd1LMm+2
         2LuLF5WIdh3Yg2hbs/V5UqxfQEtEYgAJncmp+26NS0+6utrd5Vm5V2k+WfA/q5N2a776
         MxI4BWbsgH4wedbsZ1dC+kCNREeR7HR/FlGWx9bLHsULVk/V1xAhvDHmX4ccB43h00xk
         l8Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199019; x=1752803819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q0+bcK2/AzzMDX2a7oj/fjxqiGEImPwx1w1Rqa/aVtQ=;
        b=kkMXTwSHQgX33NpUEFE4+6Bv2OJbOdFN9FtYLDiQfpM+x1m7YmZKgbBT6dmyCPfVad
         bd3YfwGP9TLIsOHOkHg0ck7GcZCssjWHb5NV4+99/ail69mH5dQY+R41fsG4lN0iHO+U
         5bRk3lh4iGVG6mbsjhH+QWpRVICmCMBLr4dxtJ4rRV74IzPWtCE4qfJdU8w98fDaZMlF
         B886Lmwmo63NnzAkctpLu9k1h8W6OQff9GlvNASUTt9Lwi9uMB8mOGpKqPclfhQUH2ns
         qm/ipvDdBSEnMwvz7X+8Bg6R7lBFWT4yD3JNjj1+EvIrnYNivIYnh9VVpmji69GI00YO
         A2rQ==
X-Forwarded-Encrypted: i=2; AJvYcCUOU8Rs1RpcFKF7JAidM/QusF+q6uRYaD34hVFTsGa4VE+lmRMB2qpOxF412yqs2IcHfz1bNg==@lfdr.de
X-Gm-Message-State: AOJu0YyagAsPG6cok/ZYdeQo4nG1ikXIhxShTkNpvKXDV/6YIVouzUVO
	HS3RGA9RWvZEVnv9N3aGhnJlty2JN+CE1wPs3hII4xIq/2vaEptbM3KL
X-Google-Smtp-Source: AGHT+IG7ydL/FNLwhCUbnXG3QivxoHay/QA/X4a2ISTMoKiO8pdz0ScE5I7/eS3K/O23yzWPTn4J3g==
X-Received: by 2002:a05:6870:4689:b0:2b7:f58d:6dcf with SMTP id 586e51a60fabf-2ff2b637b27mr240315fac.18.1752199019001;
        Thu, 10 Jul 2025 18:56:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMOnMxGjdbKJ6VILLRXCoNNHEhNor8vAT/GkR3ixyAaQ==
Received: by 2002:a05:6871:a316:b0:2e9:9a5a:7609 with SMTP id
 586e51a60fabf-2ff0bcd39b0ls556558fac.1.-pod-prod-01-us; Thu, 10 Jul 2025
 18:56:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmQiJO3bAMP8ID/xRGuY816ZTR9aQ0b9vtokYODXkrRADfTuFbwyKbDYpNP/mUi8VxGwaDWoLdf/0=@googlegroups.com
X-Received: by 2002:a05:6871:2894:b0:2d5:2534:ac19 with SMTP id 586e51a60fabf-2ff2b4dae47mr372590fac.4.1752199018197;
        Thu, 10 Jul 2025 18:56:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199018; cv=none;
        d=google.com; s=arc-20240605;
        b=XwLmkZuA7U2qTqwHvBt07+DC9jK84cKsyshG+80lcgOg0mhWsq7NiaTynlWhIYZqo2
         83CO1g/HWkMsTsf0TgzxZvet2lVVkJmcsowrE93hu09rVE2m2f+lPVaOqo/yJzFJREXc
         gTYFgnLlYTY1TXwJVeR6P3gwgGRF6tDZP4Q4rGYNO92waR5Y8M8KvhAgeUESB0HO9b3B
         4QZFBUPAZPgWJznExL0wJsT8xii7FIknxCEdOPBhIsBIKqE91lW/YFmUOdDt/lWrz/VF
         gA9mqzHD4ypoFb/LDK6ntx14zJD9rNoOUCWJjsDQNwxHyoUetZwzdGnfDW+BSOZ74tgO
         KH2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iLiApmDD9GioY+mJVcux47f72la0yRJlQGBvb8gjtIw=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=AChCZzYRAuw96zdQRBR6FgAK6ZDYwH1/gTSWgRA25UMSx2sfv71oOE6m9qefbUmeZO
         72cHW2Tx1w3XMAeAjP0/IqC3H4AzZOffpuK0EKz1besOQ4WsYeM8S5Fxxb5Y4O822G07
         9bkJblFUdwtxu9dp8rS1pns3OWOvuRcrGG6VK20lN2Wm/tdmKrrLLOQk7qKRJzUNtc00
         Z1sBXHKN3LmPbOk/3/V07OFZwKrx/gPm19lzhNLVuClW6xNwEy+O/KOGXTT7se17ZBz2
         N2awWtnQOReg0A4hXHBeh5maSm5Mhx6FOs/vRuAB1wNaoEFTLXWLw0aM0u2AJ3qU8Hgr
         MJcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ts7eRZFX;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ff116fafc8si188451fac.5.2025.07.10.18.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:56:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8D8CA43F62;
	Fri, 11 Jul 2025 01:56:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DC406C4CEE3;
	Fri, 11 Jul 2025 01:56:52 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:56:51 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v6 3/8] sprintf: Add [v]sprintf_array()
Message-ID: <9348d5df2d9f3a64be70a161f7af39ba30a0edc2.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ts7eRZFX;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

These macros take the end of the array argument implicitly to avoid
programmer mistakes.  This guarantees that the input is an array, unlike

	snprintf(buf, sizeof(buf), ...);

which is dangerous if the programmer passes a pointer instead of an
array.

These macros are essentially the same as the 2-argument version of
strscpy(), but with a formatted string.

Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 include/linux/sprintf.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sprintf.h b/include/linux/sprintf.h
index 8dfc37713747..bd8174224a4a 100644
--- a/include/linux/sprintf.h
+++ b/include/linux/sprintf.h
@@ -4,6 +4,10 @@
 
 #include <linux/compiler_attributes.h>
 #include <linux/types.h>
+#include <linux/array_size.h>
+
+#define sprintf_array(a, fmt, ...)  sprintf_trunc(a, ARRAY_SIZE(a), fmt, ##__VA_ARGS__)
+#define vsprintf_array(a, fmt, ap)  vsprintf_trunc(a, ARRAY_SIZE(a), fmt, ap)
 
 int num_to_str(char *buf, int size, unsigned long long num, unsigned int width);
 
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9348d5df2d9f3a64be70a161f7af39ba30a0edc2.1752193588.git.alx%40kernel.org.
