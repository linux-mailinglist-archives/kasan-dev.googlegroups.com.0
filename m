Return-Path: <kasan-dev+bncBAABBYNWT2KQMGQEGTJAHIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B6B09549ED0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:37 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id p6-20020a05600c358600b0039c873184b9sf3280506wmq.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151457; cv=pass;
        d=google.com; s=arc-20160816;
        b=WDpH0JZAKpb6UpaUD4I++z/dwkP+5ycUMDs5M0jW/51P2/znh0Xa/q04v2PGanMLtK
         7VeCuUXrMbSeMWAKreUbnBCmU+lcQpiOV77HYJaJ9z13V4TArzbdCYwQnTGBEiz8/Cuq
         0LdywJVjmVZhT5Cuj7RcTQHF73BgUqTo0RJKQ6e2Uj9wXAZP7REb29RU1ix1TAZFJcl1
         s7wAC2t7MU7tg/g/MIMidPkmkXbcm+6vn9JDEwmzwokZMKkQ1MBY0mfznukg5xdCYaF0
         QyAOZY80eBlmgkQPZZz2DVL3c1kqVAeKabHEoXwGPwEZCCzqZMyAXbi/iiVg2T6XFkfV
         rg1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Njbb0SI2RIT5PrIpOY2UYAf3QWCeL/lfQ5BGk9+lsVQ=;
        b=ioZAR2+VyIk0mBML7VQcHNTeaYxzMGgeIoInzA5JtcNuaCv1DAulyZKyV6B6TBLeay
         FEoZlpaBiCVfqREq85DoaIuih8Sh7385cgmds+cfq//nqVE053480aFbT3sRcRAMZ/cH
         Yv47ovNQZAPQ/qyeICay2u14RwYQg5obd/xday/uJkv1rhCVTqvLsVwrxUqBj3wkHYwu
         0rtXX5lsha5ETF84DL+fn/aXuFG1rHkyMnpit87uxY05U9i6eF2hmKdlCboH3A37dQAN
         IHtZEplLsFP+tfwYaU8iP81WHWQCfpNbzkDFokaKkNPEmKm+HRz5RMyxaoW0Ilh3+Wit
         VHSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPoF2wA8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Njbb0SI2RIT5PrIpOY2UYAf3QWCeL/lfQ5BGk9+lsVQ=;
        b=Qlchv837aZ2XSuV5ls8AaDpteyxSmd5yNzntd06bpt7lAQESUdY4tzIyzMJ8EwIgpF
         NF/A6L6bLfvUXU1twLTLX2Q+J8HEmY+DvwbtCgJnp8D2SpoEB3hDR6k5nMQc6+dgNcdH
         0mtVM1Q2NlsMwTkS53DmezmzF8bWnXfO4dmBRvuji/BzUeXwYvmy+Sko5Xb57RHN/sE+
         9iVgyzYAiOrW32z2kEznVW1HTy2wKgGh0NTzlOcq37YvswaJmOHWVqA52J6t6vKt45be
         goST4lbKFYo6p1fsmic72UOCKjTyLWYbTuW2QHJFU79Z/iy4raWIHOLFPm8R3GoenFhM
         Dbvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Njbb0SI2RIT5PrIpOY2UYAf3QWCeL/lfQ5BGk9+lsVQ=;
        b=5eaJy6sLJ5Jon/GYAe9gONh8rsUhvNdIwvxuPkSvKZ9vRTlF0u1zGPup55IFdeqZ9v
         NFdQ5YYQ2UBQ+1mkqmJvf8LjnTGruwfysUCUExURBPWEf9/tFeDzXeXa+ScaKndPIbsc
         zWCQcExOnWrvmciKi9ZMKnercrmurgt5i7JHcnfpccv10g6i3oY5BtlGm+li6BQLhov2
         hZ0lsAV5aLNOyTxI8lJSSbMGoUnPLVPf0FsEP8Sci82ysnWVSTwEdCIjiNUQB6MVi4zr
         3TUf6b1X0BbogRPnrC40QnTRTdWJRVrYksrdDri6PaDPrj6KGQnVsU4Bg+y9C7C9XeOx
         otfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9XgsRBmDuvKquxhoLUvb9ok3JavwV4QMk9Ki36wbE1HldvplY6
	PnkYl4bNpjeV4C/oFg8Ju7E=
X-Google-Smtp-Source: AGRyM1txqD1Gf5LxJxWXfQnouseVRdyhm/gd5vi0lQv0QSiHw/KTkdyWPhVRwqMdqyyAToCuysR7UQ==
X-Received: by 2002:adf:fd84:0:b0:216:1595:82d3 with SMTP id d4-20020adffd84000000b00216159582d3mr1380766wrr.239.1655151457426;
        Mon, 13 Jun 2022 13:17:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e29:b0:39c:4a18:152b with SMTP id
 ay41-20020a05600c1e2900b0039c4a18152bls127068wmb.0.gmail; Mon, 13 Jun 2022
 13:17:36 -0700 (PDT)
X-Received: by 2002:a05:600c:5022:b0:39c:7f6c:ab44 with SMTP id n34-20020a05600c502200b0039c7f6cab44mr429436wmr.97.1655151456673;
        Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151456; cv=none;
        d=google.com; s=arc-20160816;
        b=W5KIeQVWShRkfzQpBIIfrQUpa15h8fZTxA88gZAW5cTP+psjkkzb7sAw1e5o/TGjXm
         b0rrpecsT/kd1G7vLLY3jiFLWHXwxKxl0inL4ZUG5NGKytY1eM4LX2tktAwNSPHoEeuj
         FXMdJvwd8TCeetBUYBLnh8OQpqJTdBy38/qYsQZaSkFXKiEAoJrc9Ai+avdgXCgvZES6
         9/SKgWKWBBW+DwoIls35F0Mec2PtkBHemZGh9oV62wYtQAxs628RqpZC1BXDmEwnfxUd
         WdWSUMHvm4I0qpGH1hQqs14LxFnF/nRNnSsnMH91K0sXb1vhItEhX1DkgFKI7ByPsnZs
         7Gcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tSwVFyyCCOKYSS6nxmIV1PC3/qH9HgKDBeITqQWAPk0=;
        b=ynM2oJYagca6c0gNjPitpgLZYWC4CYgVOYjSViGkidjSLjAMwohozzwk+HXwwxDkum
         psmnm3hpZLNah1PSBUMLDIyk33gWQv9lqvSqXPA5sq63TrUqbE1vlTuZtqdqlPVIUtNX
         nG1WtY2vkLSrqMdkrvStCdM5Lyen9ux7iZ12IUT3oE6D2EbtghlUePJekNppM1MuyqLD
         gcooE1zyeZ9wFrMKgjl49Wr1UPWe89b2bJ8Gd0nBMdpR0HMlt9SyU0ZD+YXAqKUd1CZP
         TwmcaL0J2ynMQo8y5FsFYtI15dNQUBUTAZFImbdGRFBEWaX1kAl1qDbBAIBTjzjLAC3v
         vWsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WPoF2wA8;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id bd15-20020a05600c1f0f00b0039c53b7b69esi363687wmb.0.2022.06.13.13.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 16/32] kasan: only define metadata offsets for Generic mode
Date: Mon, 13 Jun 2022 22:14:07 +0200
Message-Id: <56df12dd774101d121cfcfbbab69d71851d8671a.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WPoF2wA8;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Hide the definitions of alloc_meta_offset and free_meta_offset under
an ifdef CONFIG_KASAN_GENERIC check, as these fields are now only used
when the Generic mode is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9743d4b3a918..a212c2e3f32d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -98,8 +98,10 @@ static inline bool kasan_has_integrated_init(void)
 #ifdef CONFIG_KASAN
 
 struct kasan_cache {
+#ifdef CONFIG_KASAN_GENERIC
 	int alloc_meta_offset;
 	int free_meta_offset;
+#endif
 	bool is_kmalloc;
 };
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56df12dd774101d121cfcfbbab69d71851d8671a.1655150842.git.andreyknvl%40google.com.
