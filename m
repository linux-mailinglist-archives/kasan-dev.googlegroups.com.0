Return-Path: <kasan-dev+bncBDIPVEX3QUMRBLEWZ6XAMGQEMJZHDLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 10BF285ADE2
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 22:42:06 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5998b7ad6b4sf5613102eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 13:42:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708378924; cv=pass;
        d=google.com; s=arc-20160816;
        b=KtcASBnySS/Eit53VxzN/TnBBaSk76Od5tWRfzQOanYPAzvuua6jZ2qheTcs6470nk
         6znXKVb0qTF3831hTIc54ZZXxwj+Ere5qwRp5xFYty4Syfvix6qUfbj5wWbZZI1qOzKe
         uVi3H8GM2llqg8ZWuUBdVlAkKJiZk4pYgKNU0un53fMnfPIEMkO4jz6xadUV3x0SwY8Y
         szJIWTihV6S9cZz2R3sW6V+K5pIvPy0r9UlQKinLwrrhJzpRJJMvD2XkSXrzR678G5cp
         jrVghKFivJfFpgTPq8/k3DCxZmZ/JrLcfVphSKSM5CFyjorhgz4sK/uNZl3CfmZGcVeN
         vcAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=6Y9hXGBJuwM25pmefNnfhPmpveyV3TVT3u9owDF5NR4=;
        fh=97SlqRxY3pxTyigYkTOnWjwNeM2Q1Gc8agZ66o+6jG8=;
        b=hwefH4MxXjV0QlUowzB68q1zM7Lt8df7a1XuPEF98Db/ZqrYzFb87XTlgt+R8/3FRE
         udGsShJWoW21iaTfGH2JS7hT2Jr+szMGRGAoZskjBdAMhKxTmeKErK9dVqqSvxLWnXel
         FnXsgjgrznJc9hS4+4JuaqH7o8oGK+nOq/9jb4lLJH0WXSWfHKUtJXtN4OIoUKVLxAqd
         yIs5lOnARLPURV0AiNbQEs3PuQTUIVB7oot77pEKirOUm7kU20SkCsj76k4OcokYK6Ox
         FolZyby0cnyOdioCrFXiXugWK3PLA078hHgqlzXb1LCzrW7O3Wrr5cZxjhQZPhJEpa2Y
         gF8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=PmJf+wkk;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708378924; x=1708983724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6Y9hXGBJuwM25pmefNnfhPmpveyV3TVT3u9owDF5NR4=;
        b=WUlX17Bu4Bq3MdVJUNhDH32WX1F56gZMf6nGrJFGLJVwaMA3vElXjcZ6gj9+NFAeJz
         UQbSwWx7xk+VtmoE5cZyjWAXJjQpyb2Jpss2hkkAaw8wG23BG4EdOCLDw0PDUbbranuQ
         tNqzdvrM+GGsPzfkXEFK5Gy+QPHgeZVrAGK6x02Ks1vIiL8JFP3OD10Mi908pdhSdCH6
         8b7/JDiHNXV7UTF40WRrkhktt7kFu4am2+bg1f2joFTVsQbEDwDRFMz6TNUmDVJw6KrM
         sDp/WireXsxIWX8PeA9TxYunnTiLNGoLzd38tuUngAoxPH/mzB+YscREAGtyywtgj/Yc
         vr3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708378924; x=1708983724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6Y9hXGBJuwM25pmefNnfhPmpveyV3TVT3u9owDF5NR4=;
        b=vTSyt4qMIQ9D7lmvsVrgbFTgcmBh9tCbPvpSL99oUxPDZC2+wbanmC1UaLYjszEFLP
         uSvYPxwD8smErKH1IVlcY8qwX20nV5Kv1mv8JH58CUcH5yS/5pT1mD6jPOhoJKN+h9Bm
         Hqh4wrAO6CHLGaIhNEKMr+u1POc/UEi1L1736EB1/NUiVZ6qjXrlEa7l1PUqg1fOPcSI
         Gwnt83DljVvvJxODnV/U/uPFCzWIGd0iC1nt9q46JaDIykRuWr70KXO6fg+PHKgiZ4ed
         DcIDP0S/OcVUxuznCS4Q74MxbuRy2Ry3TwfjEu9bPqy73ZFY5QFLtie2A4LWzVwAvNcW
         c2Cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0Z5BDYNIe2yXtEmp+0eABb7+ilaRmL8W+2WG/hsuqZ8mo+QMr29ebdtQE1M/EjftrGEWbb9FxUFKp7yNmatcGvaAX/TY6wg==
X-Gm-Message-State: AOJu0YzL8sjCEPgHfUD2YwZ3GUXYSNwieBjfskBn6oUOCDX7/XlgUSGg
	BpT8LgT0EL9IBnn4ErI5X7uJ0u8toHaFbtBre2xj3GMz98sEa4Ba
X-Google-Smtp-Source: AGHT+IET6QovCI0q2SNvb89S8lmIO8akAFBMPa5fK/eywvf+Df+HUBKi15L1Stgy+gxLTrZjHJcX2A==
X-Received: by 2002:a4a:a802:0:b0:59f:86f3:7454 with SMTP id o2-20020a4aa802000000b0059f86f37454mr11689288oom.2.1708378924695;
        Mon, 19 Feb 2024 13:42:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:aa09:0:b0:59a:9587:32ea with SMTP id x9-20020a4aaa09000000b0059a958732eals4011083oom.1.-pod-prod-01-us;
 Mon, 19 Feb 2024 13:42:04 -0800 (PST)
X-Received: by 2002:a05:6830:18c:b0:6e4:2caf:5182 with SMTP id q12-20020a056830018c00b006e42caf5182mr14019619ota.33.1708378923992;
        Mon, 19 Feb 2024 13:42:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708378923; cv=none;
        d=google.com; s=arc-20160816;
        b=nlY2hVO385fUfdGCHqagj94GUhx6wtu0S+C0THS4Xb1bDC1EHPhDqC/7RVeICNic99
         MrTMP1BOZ5sQdjU/BByMQeSj1r3kNSlgeSFOhm6ScG8mirB5MJDN5SE4zle8xZOqA4DB
         zQ7vsElAUOaWp039omdbNb/da0mEkBnOlLk6y22mLxSw0iA1Y6CaONMtl9BpguvNIMJi
         i56i51kFBl8xRspgZV07x/VPWDgtGtvffep2DgyVhu4rQKotiPd/j9Xbnp9KNTH2Twpd
         nZ5FL1msARBYLmn3QRI7cqSiaHU2ORuy7505hBKawqfKWpySalVz8GR5EEBoQ7PeOldY
         QwbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=pe+dnDgry5hhr0l68V/DK290T6uYlt4qiIGGDU/CaQg=;
        fh=MNoNyyVJM/0XbF1mfyS/49n3u1jxiVny5YsKcE/CgzE=;
        b=foWqrY80+CT9Yiw4mvpc71ecedykwYHBKe1eZb0BB1uQ8mXEESNZrO/nd+hPgSE/jx
         rSehdCZZDsflaQijz60t88E+7TxGEylKUwns1bQU7mzEc8y1TnnaxOnWT3l7pFLvoNTg
         oSafWU8581taxBfDOYoNBQy3DOVOyXhgsChhMv5Tz0+ZZEMokYMdI2N21RStlEBJc0m3
         AjD9ahESVwnHsMMTZtaTPHSN5op77ICslVZR8n6eP/Pwt0LOb2qQ1C0vmoGxCOh4ALrA
         yrGXwBckpCJOHANNuuSrX+h0jCia9TBZUgo+yRimvfOA+3aXIEE+6Dd/7Z4ghqcjLMz9
         pNFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=PmJf+wkk;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [45.79.88.28])
        by gmr-mx.google.com with ESMTPS id cr23-20020a056830671700b006e458661192si112016otb.5.2024.02.19.13.42.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Feb 2024 13:42:02 -0800 (PST)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) client-ip=45.79.88.28;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net AE3A647A99
Received: from localhost (unknown [IPv6:2601:280:5e00:625::646])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id AE3A647A99;
	Mon, 19 Feb 2024 21:42:01 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Juntong Deng <juntong.deng@outlook.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com
Cc: kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: Add documentation for CONFIG_KASAN_EXTRA_INFO
In-Reply-To: <AM6PR03MB5848C52B871DA67455F0B2F2994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
References: <AM6PR03MB5848C52B871DA67455F0B2F2994D2@AM6PR03MB5848.eurprd03.prod.outlook.com>
Date: Mon, 19 Feb 2024 14:42:01 -0700
Message-ID: <87v86km8ra.fsf@meer.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=PmJf+wkk;       spf=pass
 (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted
 sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=lwn.net
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

Juntong Deng <juntong.deng@outlook.com> writes:

> This patch adds CONFIG_KASAN_EXTRA_INFO introduction information to
> KASAN documentation.
>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
> V1 -> V2: Fix run-on sentence.
>
>  Documentation/dev-tools/kasan.rst | 21 +++++++++++++++++++++
>  1 file changed, 21 insertions(+)

Applied, thanks.

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87v86km8ra.fsf%40meer.lwn.net.
