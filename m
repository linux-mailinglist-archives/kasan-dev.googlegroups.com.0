Return-Path: <kasan-dev+bncBAABBIHCYDBQMGQETR7QCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A92DB00DD1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:14 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6fb1f84a448sf14327926d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183073; cv=pass;
        d=google.com; s=arc-20240605;
        b=gSpAX71s4Iuv488QMoZTcp9JfjRzoGhMWnkdtZ+Tee1K8zeEDcHT3SrlWPSFHtfhtQ
         pTB063vbk9URh5Mpqh2NfxcNhNw7/TP1TELAYgraPiPJViPAuWu9wb5Cw5WCl86mOWUY
         geNXwgbdQb1Alhpyl0oVb/Mw1V3cJ1wo19+myXFuXvyh0WrkHU+IlT/V7W0pE3EQAXoN
         bxpurpAwor/22twRLU2it881PJaecQQaY93BL5MbUXonwkFQpu8iL4gWgXcYqqIICbww
         1pB2kRqnkcQ3ZonLe44LxL2E9GH/0hQBtve1ysXozO9LN6A1LVIqJB30Igw6yFnYLfHt
         wpOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=y5B4zhIHaaJ1n27wUvsj/6yB87M2l/T1ByY4QLlc+U4=;
        fh=Bay/zWuOeTsQlcfWqlUIeFf369VL5eD6S7MP59lzlwM=;
        b=c4jpNiIHIoWvaGZW98d6cXz55F3b+56Xan2h1dXJCQxB4eZNZExqZDmrTN1XNbpRmf
         4DRtu6U3gegB7rrp+F2vzXQfVQYqET+Xg3jxkTvaWZaZXtoIlGjtieky+U5oV72h8i7a
         GWnKSY/V7PAHeErpc2gEh+OvaompMn3ijhbkjgKTGShEAmlwz0cgWtG2hr5rwVCcRj+t
         xg8NsgJDpfuF6alUzJawBiWGKelUrtE9/dpyWF4F+WSfMyj/2VLRD4ZXxwR9htslXqA6
         6lj9spINSQEs93nC54m8FkOu4tjGZSTqPym88ROJ0GkfEl1kxa2lQtCKqgmuKXXn27Vg
         SjUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pCHRPHOz;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183073; x=1752787873; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=y5B4zhIHaaJ1n27wUvsj/6yB87M2l/T1ByY4QLlc+U4=;
        b=dobDM5NsOu/LFbZtZI+ydQ0oKrhE6Y3icR6rAK//OpF6M33RR9a8E4zWloLxmUPeNz
         iRZ1J12obN9a5pb8K8DOZu1WW5FJVwfaaQb2uAAtFHGr3+LgOVrj9E+fnFfqxkdoHk1B
         KjefcaSsH4Oj4X6J57l1yQ26U3yRbyaOCDUhEoEHqUfmVC+19ODO2tOgNEf4edwr6VmF
         slryO+5FtPeuSLlSFQKHbkEIv1KitKLOuQhbpwj/hBgeQT3nznVAl/d5ACVE89fVyuKj
         yPvqHMLW9rNNggQy91SQBaREoUCr7t18T+9bWJcZoXHYil2VkITPcdIHfCxVEQg7OBB1
         ticQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183073; x=1752787873;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y5B4zhIHaaJ1n27wUvsj/6yB87M2l/T1ByY4QLlc+U4=;
        b=FpNMsnVSpG+MGey1JstmzKbbUvbrcGfL+la2PGj72vi2ZCkaIfgBhAUBzq0xk1ZQCg
         RWTXLEtsojyzkAiVpZNynBwq4Ib4JYzl8hjLfs0YpvwmuSHmEAYABDEd29HGG91ekxRp
         SyKjEmoiAvqiA3kctD0mxyM/wdudMecCzrs2ipVLWdKBOctEigOIH80veIc8OUVyfqR+
         EMzth7OVXPDPD3y3IltktNdZlQA6PIfRphPaGJZnLhraPgihZyKFyoGXlEx/QOhhaYdv
         3OWOUzFg/TTHMDxKzb41NTqMgG58on6+vZAvp5iTZn4jZ9ABMqYUs6FCheyZq/JtD46z
         Vy3Q==
X-Forwarded-Encrypted: i=2; AJvYcCWNfJ+b0kWgeBtcvgx2e8LbOnNVQQfCsP+vp43D9HetuKIcltVHQeAsShjjTFMc0pF6ARm0aw==@lfdr.de
X-Gm-Message-State: AOJu0Yxm1FBRpVRKYP4IJaBYPQ3VE/Ef+csMniMJdPwfy98HrWSArySC
	Q/ZjYkpZAGFEdVHKOjJ+yUiLgi3WZMjBF78CqOv4S3usrZz2zho7dNn7
X-Google-Smtp-Source: AGHT+IG7zUF2HV5J+Q5SFqfxzh4aInLmAlyhS3UtRcBDk1Ui2IbUPX8d7NBmw8L6Rar++r9Ba9g56Q==
X-Received: by 2002:a05:6214:d4e:b0:704:9b27:1161 with SMTP id 6a1803df08f44-704a431da05mr10823676d6.40.1752183072915;
        Thu, 10 Jul 2025 14:31:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzjlBuDxJJgz2tqZG68RZKVecTA60Qu0hnqnuRQAgGbA==
Received: by 2002:a05:6214:d6a:b0:6fb:4df4:35dc with SMTP id
 6a1803df08f44-704956d384els19877436d6.1.-pod-prod-08-us; Thu, 10 Jul 2025
 14:31:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0BmUUr9deneGotl8A/4TL/l/9H6wLQEBVBH5LKGteZfdy3yYYSNIE4eWqXBVr8OUrrP6OmK6a4hU=@googlegroups.com
X-Received: by 2002:a05:620a:25cd:b0:7d7:79ff:a1e5 with SMTP id af79cd13be357-7de06bbb0c5mr102203585a.29.1752183072112;
        Thu, 10 Jul 2025 14:31:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183072; cv=none;
        d=google.com; s=arc-20240605;
        b=WPD6S/ldVnxy6vqU2itk86hKFWQNH7bxobeQgjHa9YQXMwE8rKml/z2sMQqeEPi5cG
         TJ6ajfmzkV4UDma8IJJeV+k81VNmZqvRAOjFybihBhAvCQARqCr+OD7D1WqsthEusyfh
         R1cMFCPwgObwOJ1l5Id7NdNDcJlZnxyZkL62ZCY8yhu6+vEmDyHPnWq9rE2yYVk26qGU
         SB0EJC9iHH3TVz3VGxsYs2th6HrrrRJU7A9uASVbqxdvba4evRIN2qDXnN2o911w5leF
         zjj6P6mqPEHP+XHMzEwv59owL3q7dwAegmLZXOHXXNotgKV6a4h/TEGPvbjBw/PaVD/I
         rdiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZTzMdAzS0MUZsG3INWu7KjxgVxyuWBJkeq2Ek55G1bY=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=Z0r573ApzPQFDC+ZuTbcIjH20z2EiaOOdbqnq7cI8eUUOq8SMp3Q0ryDhGsd3Dx8mf
         BFl2r9giSLx1ljjznscE4U8rWq9Nx91lkyC5UGtP7BtVGbVeATPEipgeneIWphjuRS6f
         Of9Y1jIDuDxouSuwnMJ3Tofs0nkulHONLUi65GomQwSDj4G3lDf+a/eZpDRvPuZ/+vf9
         Vky18oio6GS8S92TfxHy/XFsMwdeukTE/kkspcWwokXu/73k+CfXOx+roJ1VPXi12/Pv
         LJFY09oXXRjvnp0sqTEa2F2q7/vmfSRZAHGtRAr8sg9ZiOnbbGvE/hMXCjaYFTdutAfC
         Bb2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pCHRPHOz;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e8b7af49869si92067276.2.2025.07.10.14.31.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:31:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5825143B47;
	Thu, 10 Jul 2025 21:31:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9C0EBC4CEF6;
	Thu, 10 Jul 2025 21:31:06 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:31:04 +0200
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
Subject: [RFC v5 4/7] array_size.h: Add ENDOF()
Message-ID: <e05c5afabb3c2b7d1f67e44ed8a5b49fc8aed342.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pCHRPHOz;       spf=pass
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

This macro is useful to calculate the second argument to sprintf_end(),
avoiding off-by-one bugs.

Cc: Kees Cook <kees@kernel.org>
Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e05c5afabb3c2b7d1f67e44ed8a5b49fc8aed342.1752182685.git.alx%40kernel.org.
