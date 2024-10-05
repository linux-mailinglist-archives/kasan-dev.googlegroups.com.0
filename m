Return-Path: <kasan-dev+bncBDAOJ6534YNBBIG3QW4AMGQE5NLXAOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B826991867
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2024 18:47:30 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42ac185e26csf25132385e9.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Oct 2024 09:47:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728146850; cv=pass;
        d=google.com; s=arc-20240605;
        b=hvABmDEgI+6ElemT7dfyCvBxnv3CHAVsBfSFdA+VHE/1aM/nRkWW3cC1vDrHZy9yqM
         4Ezm5UBCFtTVNvXba3kbu8JJjhmPLYANdvd6bJOR4BkTwZwqUTgWFrCCMGwLKZJcsl9W
         Z9oAmgKBOqdlelRmy78cKVYyqtZNYnrYCOUkvwVX7CP1a3MzeNRH/1fYP1TnPaowit6S
         Yr3mrScpP7NWBoomqkUFED337Aac07Sdjuvt1hkFgawEiVl6W8NJtIwTxLMsQ0T/wABX
         zEeWq2U+8rOu+WHXg7Ag45ugLdINPyWDaPrPRC7xB+oONs1c5UBh4mfReRMVqVJOFkEJ
         z9xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=y6ZJi1GNKxnenvI+T8J7jEIp0NOC/VTkovzJnOi8sH8=;
        fh=2eX2ilYL2zoadjescxgOJfGgzy+CARhlXOdf87g9dx8=;
        b=UsjVGuhyxzevcWoQmMd74pWIP+WQ7XMfklu3DLziAUiTRCPS0KwLOZwW9MIjSAWc6B
         czjTZtLCBpUCH3uQ3B3ostDE6VkGYEddDfX09QF0djIgb9+W85NkftnHd1VKscbRhNwJ
         9HBTpQcBAGxG3CBDYzaX8phxblhj5QuROMpElqWo80/JoqRwp9YQWQHyVTnlyyl91ZoO
         bCOLflE6eRiECL5XcdBm4pMC21DPTZdYQeSGeHcSA0IRPjmtYMaG+YCHVA+inyKjWpxV
         HldiMfSOxFurfBVW6pAit1F0DZpe3E7I/MV9KZkgz8WC1p8wSwKogDxNV4Rn0hn2MF4c
         FGqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JKdbgpAk;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728146850; x=1728751650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y6ZJi1GNKxnenvI+T8J7jEIp0NOC/VTkovzJnOi8sH8=;
        b=inkWgCVGDaNXqJCrd+NuERbMsQhMaPSVCxal13oq6fwNi0EwIy9O7Xfi4Lwhmseg1R
         2R5SmVvzF4sNWYz4rZnCP9nOEWt05QVo4SNpp/AU1xadNnfRjNC2F+S/QCB3i1c9sVz8
         Sad5oc+wqRFStFzv4G5vboJjMscBv9wKAovsWMfQ9OfplJz7sMgdUR70wiCvVyVYPR17
         NefLGHDFttJt7+O9pLi1E2g8MtOwOcGZLVlJEBa9olLadtZDf3HK9jvOZOCeM7sbzBls
         zTxJCt7On+VdpKMX0MT6wk560zze99eAaf0TGvjXC6BCxFIN7jD81tDfxzF6FR0u08R/
         xXNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728146850; x=1728751650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=y6ZJi1GNKxnenvI+T8J7jEIp0NOC/VTkovzJnOi8sH8=;
        b=lRSrjHeFmd6fs4iAlGXAJ02RUii5oktdny1rcEJqfzHSwNvkeZz2xSuGEh+17sfAYG
         NdrLCVsCuGzsNW3DknwzFw21A/nvImCUvJyRm2RkHVW5PdgU92sB98d2qa+KzrGSEPee
         7m4J4Vn4LdhUqW3aLNeeHQysEM/WuMTYkNsO5Jo+QNsbtKcd5sIIKzqteOilzv/hfplB
         tr8BL3kRmnlX+eJwNjK8b3rXl823JnTAM7xwX5FuoFh1QPrHsFfXxgJcIzKZVwkZJeC8
         YbdVK6DfvCY4rH6n8OVuPRJUOtVzodDKImi9Y/dmvyZ0UiVOswl7G+57xTy9hwhqZ49F
         LCNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728146850; x=1728751650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y6ZJi1GNKxnenvI+T8J7jEIp0NOC/VTkovzJnOi8sH8=;
        b=v5BxXpNmUqheDLzyBEPWIegQJAQ4Jear1LKp1x0DMtK9tgQ0T52Qg6DehTyanumq82
         T8oN7XWLV1XnHvGsyXsO6Qe/t4dtNQKGW+4cPEBTErPpUteaBpDqhQKyxi3+lE3DCzmb
         Mu0VMXbOsQDB4Bmibgry5xME/iT3c5WGQftVlMmnYrSYm9LLdGBnMEYLNSiGsBp1Slyv
         Hr3d4zdMmirrHSCjwl8WAZ8x6ztTxr7M78zP+vzuvU2/2GVhiURQHTZJmX5DEvYcuqcP
         qhQGsH/wPzeV7wuFLcV85+92L7jCqrO/zy3TcE3Ll03FOV7Gt/HSSXsypZMAfBD4iR/f
         /TZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPtMxG/NxZpzXA/tMo1+T4T55OyClC3N0d4mwdy4E45HImsKvWbgD4G9a8JOzYQkNaDcA4OA==@lfdr.de
X-Gm-Message-State: AOJu0Yx9gZBzVaXGIFcY7+YiU4HQKWdKnQEVL+I8W1IjyUtM0uWgfrBI
	WAz728Y1MZ6KN/eqmxw5wZIdCAyfm9ajaayo+LWBjENueoEvxeoF
X-Google-Smtp-Source: AGHT+IHqHK5BWku6OqUnIipIEHGgqXTLlNe0/P9WxuYblFv4iM9BPkL849jT/7c/H1+iwB/mToXZ1A==
X-Received: by 2002:a05:600c:19c9:b0:42c:a8d5:2df5 with SMTP id 5b1f17b1804b1-42f85ae9195mr51242295e9.24.1728146848392;
        Sat, 05 Oct 2024 09:47:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4684:b0:42c:af5b:facc with SMTP id
 5b1f17b1804b1-42f7dfac22fls2157815e9.1.-pod-prod-07-eu; Sat, 05 Oct 2024
 09:47:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy/8EAou4I0Gh+RoLNIJEDszsd6+ziNukOZZdmUxblQq6wApxAlTzo9jgDjfO21Ul00mGSRv4i3Vw=@googlegroups.com
X-Received: by 2002:a05:600c:1d99:b0:42c:c003:edd1 with SMTP id 5b1f17b1804b1-42f85aa9d09mr51600445e9.10.1728146846412;
        Sat, 05 Oct 2024 09:47:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728146846; cv=none;
        d=google.com; s=arc-20240605;
        b=dDFTFbqK3m1kTUIi2xOMU1SvV8TNZkgChc1pKYoDVGEt+MnvDRJIL8kOPUyMY4SaBn
         k8Ol0mhwJU8T0N4VLq6XAyWUNIkotHUmrAuFS+y7ObM2v3sKL3Q21/ZxptqPpWsyDBE7
         ouEc+D/jMLtwo4jxv9S4W8kGH0obr4i6kgQRoMg78FvAvM6bSaAjHNgtWmqa0nUkyOZy
         azyv6t22ekTa5YQhCeSkSepVSufOhfKO/towtjrDnrb96r4bujGiIwBFxBlVJBS2SmSP
         dCGRBi9g8JCXXT+7URuCfVdm6pTkzyf8b3GByViCuj1wsNE/Mt6h7+gFfAuvifmtUzJW
         bbTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hj1spl/h6f2LGGC+51xwjkCU2sNccvLDpAszxwH0jrg=;
        fh=HTIhtQ5gHJUTdyf7YlTReIrfOw6o/NWu5wmtDm/qWWE=;
        b=FwX2GbXRmFLuY1fmNhsOI2hokb1OCbQxgbIxpmk/zvkkxTM7+Vpv2NMdvP7E/rlDmE
         1KTOp4bhMtD7Qhte/eO8oJ5upY2Yx0rcQ7mVPLOrqdkzW4xWxo6fh/PJqeFHEBZpmICy
         2CAL4XRua9rXXnIGxNwQbmTD7P6ytjwsBh0lcaTI4V4q9YTNZVp+87Su1T0ZBwSNu2DE
         z6ZKyJhi6UTHfMAThiFE2EE2bjdmkuIRjQ9bDxS4jbXayAGoK/XQtlLEn9DiflTQr0MJ
         r8Ks1H89fq62IdOL3Pkb1+PBT8YFId4A48jmldKeVKa/aJED2Qx1f3tJgSz8n1l88hn2
         tmCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JKdbgpAk;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f86738814si917325e9.1.2024.10.05.09.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Oct 2024 09:47:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-42cae6bb895so30050985e9.1
        for <kasan-dev@googlegroups.com>; Sat, 05 Oct 2024 09:47:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUPOdD4IAA1OGs3pJpUa4jbLwQrjzGlJA/3Eq1CostuvWUom/aGDJR/NE8UHaTmP7BGBkOuLRJj2w=@googlegroups.com
X-Received: by 2002:a05:600c:3ba9:b0:42c:ba83:3f0e with SMTP id 5b1f17b1804b1-42f85a6d73amr45501295e9.7.1728146845616;
        Sat, 05 Oct 2024 09:47:25 -0700 (PDT)
Received: from work.. ([94.200.20.179])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f89ec71aesm26481515e9.33.2024.10.05.09.47.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Oct 2024 09:47:24 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: elver@google.com,
	akpm@linux-foundation.org
Cc: andreyknvl@gmail.com,
	bpf@vger.kernel.org,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	snovitoll@gmail.com,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH v2 0/1] mm, kasan, kmsan: copy_from/to_kernel_nofault
Date: Sat,  5 Oct 2024 21:48:12 +0500
Message-Id: <20241005164813.2475778-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
References: <CANpmjNOZ4N5mhqWGvEU9zGBxj+jqhG3Q_eM1AbHp0cbSF=HqFw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JKdbgpAk;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::330
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

This patch consolidates the changes from the two previously submitted patches:
1. https://lore.kernel.org/mm-commits/20240927171751.D1BD9C4CEC4@smtp.kernel.org
2. https://lore.kernel.org/mm-commits/20240930162435.9B6CBC4CED0@smtp.kernel.org

In the interest of clarity and easier backporting, this single patch
includes all changes and replaces the two previous patches.

Andrew,
Please drop the two previous patches from the -mm tree in favor of this one.
Apologies for the confusion. Will try to minimize it in future.

The patch is based on the latest Linus tree, where I've squashed
the latest 2 patches merged in -mm tree.

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

Sabyrzhan Tasbolatov (1):
  mm, kasan, kmsan: copy_from/to_kernel_nofault

 mm/kasan/kasan_test_c.c | 27 +++++++++++++++++++++++++++
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            |  7 +++++--
 3 files changed, 49 insertions(+), 2 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241005164813.2475778-1-snovitoll%40gmail.com.
