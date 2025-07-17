Return-Path: <kasan-dev+bncBDAOJ6534YNBB44Q4TBQMGQE4IYWTZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E52EB08F3F
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:05 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5550e237ad0sf550054e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762484; cv=pass;
        d=google.com; s=arc-20240605;
        b=YqPfBcslUcgI4wgoJctDxw3MksBufivljOCaGaeaGwxIrPs2ArMWt4eZaRoPRpJ3P5
         b8sf6e02wMBWQMwRhmuFsmoCtZiozmIez2JkHwtPJEH9ewVtc2jqrMAH7qO2K9n3rP82
         lHrQ0JX2y/Q4N00nG6TehbKjeaACNHWz9aj61n2gLhm4Nu3HWrvElkzvPBzVbxr0QUZb
         GAZUTzAdSXqHSxFPFfZVUUoBHKPLgCNYDsrzQONvaSr0Mv/R/dwvUxB4b4W0ayweahpp
         ld3ePujKcQ3ontwn9bVJRHJ5iFK9mZvz40DXzO2sbn5M9JuVCYdccnDANudWblzc7f51
         Rjsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ffxKBE/jFdiCJq3EAbRU+gtHlMjvMTjhe3k87QBL/Kg=;
        fh=0K9NWMiddD3UFs9WZbwByNcG7mRdNZOnbpJTBXsJT0E=;
        b=IarTYvglDlAh8Ca6AtuwRlGE+8Dekut0lGvfGr0YW00mrpTw0DDBhwNQba12xyLflT
         G2B4eLYG84Wzkd91jqjTWdGLNND8ggKbR+zfUvH8f3sRsUdZcqtas/7a9EsSDdaAPSVY
         XVMxWpvqc4mDlvHgsWTSjeNk2/8RchMXYn6fSjQj3cC96ep0q+detE+WsgbBHBhttXkk
         Kp7QrIGKYyyrFFg7j2a+Hx7ESE6DKndxjQTbiGUG4IWF5PqZ3kVpRt2F79ghbP79UtsX
         U4Ep9nnUb3DJAPqDdFZ2SR/L8YxG2LsiSRTFfcTZJVaESHjQNUgY2/gp5MtVDaRwetvs
         n1Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TMIx23kK;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762484; x=1753367284; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ffxKBE/jFdiCJq3EAbRU+gtHlMjvMTjhe3k87QBL/Kg=;
        b=wBIZfsKZgz0tQwe/KdG4AXMfvM01MaSlbrYTmpHmg/9ZxBdA1HLpyjTRxhg1KSdPYv
         Uf/gkaAwfsNQJODf2/2MyrRA6t93WIzSM3aVF2YkVrpVJIuAWQaLLndNyZJOtEfVNXEe
         UYdyodm0zEam1jJF+fe53N+LdA619B4JbvVIg+IFt9rMEsUTjwhJAwAePriLHMuxFsRo
         J0kwcFKuvD1KqjvQBY6R6YOteWKfv7oXR9HQJ+q7K7RSLZxnik3hskuzx0gZt5kN0O2/
         GMz4f2cmAx62tjZY0qjBTSIVD77A4hT3dlAUlecdG7st6j9zwTbz2xR6d38PxUzKZoeV
         dLGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762484; x=1753367284; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ffxKBE/jFdiCJq3EAbRU+gtHlMjvMTjhe3k87QBL/Kg=;
        b=M7n1oiTN+IyUGwyVGppjwiTIDmH2j9Ht/6nrV83bTEyqzIQLOkJlz9wTNXcPK0ibrH
         4WS/S5S56XjiWkKkTCgmno4z4ywz85oTjXyKUhC/0+g68d8yAyDqmokpcjGIlFcDqosA
         7ZbRfqwLp6GqIc6HT6W3AaxZ7/hkN+v6k2lhGD24g+q6Y2XM8HesK9ZuTIHuw+aPiozu
         AtJRHy/AG8YJH6RTK8wVvuK04Rn1ZjOlgctdBww+zanI2Q8wjm070216n2DsIDGSblfX
         6hrf29oByhq9leuoS2+1lEHWS0zoFSjC8bGczs/0TA+HNQ9vJ72if8eVG8JdN7EMluGV
         vQRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762484; x=1753367284;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ffxKBE/jFdiCJq3EAbRU+gtHlMjvMTjhe3k87QBL/Kg=;
        b=N0hSygW7UwqW32ORBQxwwzzlzvwCozHDGgB1a9wXwXbq5va3esfW9QXWlUXfTQYm68
         +LS18zjpWkvmQsHIWaKx0O/jje6qgag9QRxLB5nnn7JUf2IglQV/1/O3KuqcKUVLeySY
         QW7GBbCvPBLGNmib2MEv/8LnXls2mXl3u1Szm43N6QFaxn9013FCYmI2muednO0Bi5yi
         iD2f23mXsnrDSY47MQ/bTFf33oQcpfydhSqH8Fp7i8paSo96ozb6oxtORT+kB/BF/eXU
         FrX6J6cdGT7f74P0f0UvYXvfqxAKSbqzAkLdi5C9cF18OD4io09vhn31dmSGsGkhug6D
         DnKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+I5DEpKDGiTRtJ/YMRbgz+4mUwUsQqxgiTHimrHS6aWqx1wNlQ6XyU9teaGywOVu1lEkoIg==@lfdr.de
X-Gm-Message-State: AOJu0YyIFTRdcKPBzaQIgHVCd1VlG+3AHIx722muYCpkWNyDayr9rRn3
	302q2T4/4jEZx4tqgJlx+wLVRzEjjcGhLMt+/LheW21a97TKyKDj3P7X
X-Google-Smtp-Source: AGHT+IGcPMy8/ByN4hRy3TfNf5SsoQpH1rC8ttm8GS/saIVM2uM9rMWvbWEfCSKb7SyYw5JpFRPRkA==
X-Received: by 2002:ac2:4e89:0:b0:558:f948:b57a with SMTP id 2adb3069b0e04-55a2338aca9mr1854749e87.37.1752762484326;
        Thu, 17 Jul 2025 07:28:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevgDNqi4k93sgYq5AVoUcMiL6A61PfogO7BAeBEOG3rA==
Received: by 2002:a05:6512:6287:b0:553:d3cb:139d with SMTP id
 2adb3069b0e04-55a2decf063ls82698e87.0.-pod-prod-01-eu; Thu, 17 Jul 2025
 07:28:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfN0fQBwnYK9PT40cGzIKlG2t7y+wja2ES/ynbLPRZspCe+uPSPP6XN7IhzT/RbYYz1jlxGfb3zhU=@googlegroups.com
X-Received: by 2002:a05:6512:114f:b0:553:acbf:e003 with SMTP id 2adb3069b0e04-55a23321057mr2181216e87.13.1752762481330;
        Thu, 17 Jul 2025 07:28:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762481; cv=none;
        d=google.com; s=arc-20240605;
        b=JeEVehfrubU8hGVhs9R4wWW2dqOxTcpqLWkK6PFtsQJkxYFI/lmODyBU7ixJ+sJ9cJ
         1m30PQ2Nb8m86cbpo6V5FKl7EKE0eX7HCsjdMgUyZLIjcgaGGEB4YulY0wqYNaDbzSLv
         4ePFBfsGSb5Q3LIBk+LisFlVx4bkwwwUyRlKfDE/x/mpXPbUZbLe0HW8AY4JqqrozqXf
         0h9wSkqERzih8PRdP0426AxEcrMGz7TjfOS90kbTT+AM4gJUdr+d1jva+gLNfUVzNgS3
         RQYDZvdWyd68DNe9iclUy/FlZCjgDlaXiR4/8Vs/FrLa05YNkzrtdOD5vj3W95WXMC4w
         1X9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fypRqRD7duJ7p6/XnMiehAY4t+I2qqoeS7XCKLtEaPI=;
        fh=lzHrmN7U+e4ZeoTc5jFgnjN7xWTMXvxcSp1p97P4XKM=;
        b=dwjSVwNgJeXHZeCIZXETESwP3m/bQY9UznqI3M8hcqDBVVlJdmEUedWXHruKioZD1U
         HzIFP1NXGAtjw8f0Vop8QHAwUMJRek+SyzMoeYaDg8IZUQVlbXznE7dtC1IOp2lqa1M9
         igc3QEOdVC1aUygK3GXW2nvAvg9SftfJEdRuA2Ws6JopojBj++Pu5yV18t+cBlbq3oFZ
         WR5rzMPYM0EXe9aYa39BHcVD/VXllVx8xM9wimfh4+fmDwzsbhJODtJzYzmX0jQV4KJ5
         IiY0v1P83/uZLfrWBHFRjOtlCGuDdcBCduVpAwaTv+pK8oOY9fkLzUMVa1TDB2KfJYIZ
         iD6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TMIx23kK;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5593c9bd011si294373e87.9.2025.07.17.07.28.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-558fa0b2c99so852277e87.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIp2uQkWHM0vXgzvKVF/lv8mK0rphNJl2Cwp2hlKq/fGv+HnqvuztbvdlaZK6u1/BvfOkyo2Tqy0w=@googlegroups.com
X-Gm-Gg: ASbGncvFSHdnwdqEFO/JDi1CsFHwj5sq43JmdGgwMA/XT0HVnLGDaLt2qs0QatphstG
	GA2Auou1iZ2pYJuP/gBLiMN0XFffYbuEzU+yIOaSwAgfwgOgcMLGKVwmfSleb58LfOUKsAPkHe9
	CHSfXShWm+OOecbEwNjIWHKK4L6KWXWnTh1l0RBYBBGihufzJ8LYSz7bMTWPAiZceB7Lf5kT1X/
	YC7XbezG5BZaSFs6oyjewx4QGyHBRQDBJPc54jAtLxMfNY6TBJz4mD0vCb2odVMivMz8GNvgniK
	vtjngB6Mrn7kgJsrOy1Z8q8p6wQgVWn2WfrQjUSO1lzPTkNGBbSfSW+Zv516qoIvd4MQud1Y5kI
	gqgMz+/esmFUzVefvD5ZISimasdKhTWd3dhEk7EXlnKp1Ru4LUW+dTT3fF+J0fX1xB7g9
X-Received: by 2002:a05:6512:63c4:10b0:553:ae47:685f with SMTP id 2adb3069b0e04-55a233b1914mr1997025e87.38.1752762480616;
        Thu, 17 Jul 2025 07:28:00 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:59 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 06/12] kasan/xtensa: call kasan_init_generic in kasan_init
Date: Thu, 17 Jul 2025 19:27:26 +0500
Message-Id: <20250717142732.292822-7-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TMIx23kK;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
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

Call kasan_init_generic() which handles Generic KASAN initialization
and prints the banner. Since xtensa doesn't select ARCH_DEFER_KASAN,
kasan_enable() will be a no-op.

Note that arch/xtensa still uses "current" instead of "init_task" pointer
in `current->kasan_depth = 0;` to enable error messages. This is left
unchanged as it cannot be tested.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/xtensa/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173..0524b9ed5e6 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -94,5 +94,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-7-snovitoll%40gmail.com.
