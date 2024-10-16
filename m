Return-Path: <kasan-dev+bncBDAOJ6534YNBBF72X24AMGQEUOIKF7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 86A5C9A0B33
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 15:18:17 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539eb3416cdsf3265361e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 06:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729084697; cv=pass;
        d=google.com; s=arc-20240605;
        b=I+953I9+zTq4FPcrkwjVU/Yt8+DyTlLOfuHz97SgjAZR5JdVNykSLYLdlVH7WtF2vY
         psQk/qEQzzdeyLfT4y2tl6cUw0trsolWIKwjxTr0QNwgp7wXekGQpPIYXcmAqqjPqX/b
         j9cRPynxOAjeWnobpi1qHaBaBuOof3t/WH2XHWTcb+JdoNp41mQxRclsgjk9/1vRsY3n
         nnrqaPm8vesJvhcRQbzDE/9lwtiNp4PWRoQhN7vcBjaX8KVO7af2u9UyoyCWnpMCoK49
         gr/ycRo5esaVgseppQqxDneMi7/CnhbqpK0xweCjwJP4u4hugPCJ/TEBz5WMjLjHm5SA
         LPgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ZZxJQXOsp2MXBv2SivIv5XQB5wGqkHuQre3Jck3I7VI=;
        fh=V9oPC0B59znB06bCNIiVFV7oA93LGy22E0GeTA4GrXk=;
        b=el5klx7dKySfQKExak92AeblLqyy3/H7oF/l97Dmj0sjoT7f+RqSBg/updREe3IYpg
         3wEo10QmeocrjYgPIBfeIjuWzla0YXtHj7msxEI1Nq6vDHUVvinNBZ98t6RHGNqAdn+d
         dBExvq3hK1B7WOZyTeXJKvvlUMIpT69v+JC74ckxw+T34+yi6GJ+8KSaMPzMxu+hx7AD
         T5Scdkl3kHuhg1RBfu+sgrkePth1Fi+jtJSKvJGcMekMyUlVw4qp3r/JZX/0aZwfNk3v
         9nKoVy0OhWbw2hoeswCHq0rSUmtURfSwfhsZ+q2v+RHWabmwrtZRxQkN50YmTcRrkhlU
         4Nuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a4fQEvQq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729084697; x=1729689497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZZxJQXOsp2MXBv2SivIv5XQB5wGqkHuQre3Jck3I7VI=;
        b=tvdKJyCV3QMMqpncqma3+oTsGB4zeaAnl5oHj4BkSg+GqAbBLrOTpIFyDWpnvaEvF3
         Emz2FOoSujN7+iVZua7ikD2ER7bQS6LDV9bPsY7bD5Vltp1eZBbnAx7Nu78jVZBI+2Fk
         rXouxx8viQa2W2Zcs9YkVgE/bSW5VzpBY2uf+m6+71Q9uozptWW8bPOu/lAxQvSGzrdx
         DGZDF3iPTkcXhndgl2c4FcbPzudA2wei2aNtSXqrjqytMEBZlIl79b0UJj7LOqs4bCxx
         g6JNsEmd7lnTmZ9sQhs/+PyCDfBvCoO/xgGLR2LBQNeY0d8S38iOX49oC2tfkgYFcrm3
         ImNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729084697; x=1729689497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ZZxJQXOsp2MXBv2SivIv5XQB5wGqkHuQre3Jck3I7VI=;
        b=VJixLQse9RhJjGMiSS51XjRnfXSvWsJVD7iWT26ciok+ah5MlMVWtMzjwKHXumD9hG
         qnAdUdRPboGUBzBXew5kY4SCiCBvAEj6Je7lll3TUfKMERKEeemNFmYqAPpyJeNjkDCb
         iWO+RWOz/8Y25x7u2sOwzTtE7+FnfO1F7COxLFaZYHpPhJyNbCr8TA+qgzp9NmIsopGz
         gam8Ehx/e0dHxb+Y/DtYXixQgPmSVe+DhO0ut6lnTW9aIwkxiDqwdWRxyY98EiB3+zbm
         U3Sn1wBH5+T/ktq09DBcs0JKOTViCBLJuFHrSRm9FCUcEIAcSq62UIIriJWfA2pFc4bs
         4kPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729084697; x=1729689497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZZxJQXOsp2MXBv2SivIv5XQB5wGqkHuQre3Jck3I7VI=;
        b=o3BhbTsd8lGVWLKao2T80V+oTfcyM5v1W/KBYgy0iu/1gHQ5XKGxf9iLjxRCVZYP2f
         EUrvS+2OrhCbfGAmWFLF2j0Hktp1s094BdfUKE+fnMMQdu/QRQA6lnllWbLTscS7htaC
         YlbZ6C6tVglhYAiCMe05hY+NVPn6PJOv8VeoCQU3OV6e5SJHFgeakZJD8z/+kcO7n15y
         Wu93STpNAq7/lZidYjEOsI5rmyTaz6c3ZEtt25MDE87vtO5XyEkIQk6uPbk+8GjHj5Ic
         HYu4gqt9bnnDYCi/6p0bNF7/K20Z3OqtSt+sqp0mfzljL1j+s6cfVA/TyglwLzLBHR8a
         nNzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUT1OSdN4t7TTjfqGeolYCAOJGrJUMP1XQUvuIGD0BDzNaj7lxwAwvmpERSOAz7HH54YrOorw==@lfdr.de
X-Gm-Message-State: AOJu0YxqOWe9eGTD3JT9WsguOSmipajGmVeUweggCDj3i51uVWHpRw7V
	MAQayoxEV4a911VozHwSzY5P+9zILR2eWPxw9aIi2GbNSsFgAQwa
X-Google-Smtp-Source: AGHT+IHheRv3lNl8WHCgN+Hy4QZn1pF6rshp/gw7s9ucQQpmF9HsiwTwXFxNgL3w542EA8k2LMWCgQ==
X-Received: by 2002:a05:6512:398f:b0:539:ea7a:7691 with SMTP id 2adb3069b0e04-53a03f8244fmr2275132e87.47.1729084696164;
        Wed, 16 Oct 2024 06:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c28:b0:430:52af:6691 with SMTP id
 5b1f17b1804b1-43115fed521ls17905645e9.1.-pod-prod-08-eu; Wed, 16 Oct 2024
 06:18:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVB5A5LFspRTrebVpy7ewcl2M9Vk84rK/v4+67+uL4VmwmVLlMBcLs4eyUyg66zWIWyAT1PShZL2yc=@googlegroups.com
X-Received: by 2002:a05:600c:458c:b0:427:ff3b:7a20 with SMTP id 5b1f17b1804b1-4314a35ed0fmr29190135e9.27.1729084694176;
        Wed, 16 Oct 2024 06:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729084694; cv=none;
        d=google.com; s=arc-20240605;
        b=DpO3UIV/505Rmd1v+bj9dqSwt53+BxhU3I0ISaIePchQNvHbftbiFfs4/CfEFzdUIQ
         40lXOUKWExDaxn8VfZM1ruNBqK48apq6OAU5J3f7I9uF6ydbRL5GPvjGChvAsMNn8QrS
         FEFsWJpoNZRh50Umhnc7vadW85SwZxR6sElEqRQTeDoWAFVWOVoMt7RXZSpVhqPHeLc9
         imUeZhj5NrkKDhNo8LZf2rA4+xJTP7f/DQjsvChZFyiYjcZiWK745xGexZ7sFQwoR2yt
         a1vxmy6bCJjLzoTJPyX7Sr+tdt1b7tYwhTrQ7ywTwD3x/gnqqgndvzBfDHA0Pvi1Tr6F
         xMng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vp8mlzCFerHZwOQsdYQzAEyYccT5PlBtmx7TKcs3NbQ=;
        fh=0zR+hGetX+PCiJakF6tk1I+92erqWevXbA3OEZ9SGyc=;
        b=WFYLNbXf3WnSf123A8HMHzJ+drECtRMyBnhCp5dK1deURBQcLiBmV6TsjNW3NUjSic
         NpsuQIr6+4Ryi1afb42L8trGkF+pLD7Nw100AvCaNgfBRkOdzGACeUyKZMpun18dJIop
         90PSaeoEeXSwM9vY+NeoCq4jeEIBMJ0Kc69CQ1ftNO94oU2VkHsN2DxfaoBilrEakgHy
         BvkU2Eoo2lP1NzSAFRcu6tJe8FjnB65hVBQrGAylQu2UKI/xp0Mhrmkrm6xr49Yt6+7p
         abwJ6J+VvnylGYWuL2xZlmZjBq+J/pZgf4IG/JWU+zrcSUXbVQikHkeFtWQU6TA/OIFt
         W+vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a4fQEvQq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4314fd1ac2csi306635e9.1.2024.10.16.06.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 06:18:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-43111cff9d3so50245215e9.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 06:18:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3k740a21KrZiBQFaVIspspgiruaLqk6bgxTeNCDmWzOhgyh5YZKB/IulV+8S7eq5/9yhCYP1jNAw=@googlegroups.com
X-Received: by 2002:a05:600c:4514:b0:426:60b8:d8ba with SMTP id 5b1f17b1804b1-4314a362525mr29799615e9.28.1729084693271;
        Wed, 16 Oct 2024 06:18:13 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4313f5698aesm49612825e9.11.2024.10.16.06.18.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 06:18:12 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: andreyknvl@gmail.com
Cc: 2023002089@link.tyut.edu.cn,
	akpm@linux-foundation.org,
	alexs@kernel.org,
	corbet@lwn.net,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	siyanteng@loongson.cn,
	snovitoll@gmail.com,
	vincenzo.frascino@arm.com,
	workflows@vger.kernel.org
Subject: [PATCH v4 1/3] kasan: move checks to do_strncpy_from_user
Date: Wed, 16 Oct 2024 18:18:00 +0500
Message-Id: <20241016131802.3115788-2-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241016131802.3115788-1-snovitoll@gmail.com>
References: <CA+fCnZf8YRH=gkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ@mail.gmail.com>
 <20241016131802.3115788-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a4fQEvQq;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::333
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Since in the commit 2865baf54077("x86: support user address masking instead
of non-speculative conditional") do_strncpy_from_user() is called from
multiple places, we should sanitize the kernel *dst memory and size
which were done in strncpy_from_user() previously.

Fixes: 2865baf54077 ("x86: support user address masking instead of non-speculative conditional")
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 lib/strncpy_from_user.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
index 989a12a6787..6dc234913dd 100644
--- a/lib/strncpy_from_user.c
+++ b/lib/strncpy_from_user.c
@@ -120,6 +120,9 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 	if (unlikely(count <= 0))
 		return 0;
 
+	kasan_check_write(dst, count);
+	check_object_size(dst, count, false);
+
 	if (can_do_masked_user_access()) {
 		long retval;
 
@@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char __user *src, long count)
 		if (max > count)
 			max = count;
 
-		kasan_check_write(dst, count);
-		check_object_size(dst, count, false);
 		if (user_read_access_begin(src, max)) {
 			retval = do_strncpy_from_user(dst, src, count, max);
 			user_read_access_end();
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016131802.3115788-2-snovitoll%40gmail.com.
