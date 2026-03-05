Return-Path: <kasan-dev+bncBCSL7B6LWYHBBD5IU7GQMGQEAYIJSJQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id oE9lHhLUqWmaFwEAu9opvQ
	(envelope-from <kasan-dev+bncBCSL7B6LWYHBBD5IU7GQMGQEAYIJSJQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 20:05:54 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1252A21736A
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 20:05:53 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-2ae5031c6c5sf216781175ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 11:05:53 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772737552; cv=pass;
        d=google.com; s=arc-20240605;
        b=d3ZlxGWWC/WesKzAtCVLL/r+djknhfgVMvHdu0BWQ/1Ulk2JdmHlWxuD+GDP7cOSky
         Ui2teRK68evVgBt4eLSYN6CePVg0n8JPBiuZrlXv41shyUUUpkLEEmNpBIA2f4vBe1Zc
         +UlhCMc91fFIoaxUAu3HN8MSZbNuJ+awqKLJHlKCKYxGsdsROZfVL/eMUPG3BQYLj2oO
         hLPcoLo0i8XWwIKKDrcySnS+7SMGzw2fki8sGhhiNc7+V32U54tyArpNrJIaRwagD8r1
         QOd7VkMJDzEiVfhaqPfBE91IOS/P+qf7BBMj7QlUQ5dSzDNm4XZ6YKhjyzOH+qbA9GyN
         jPDQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date
         :mime-version:references:in-reply-to:from:sender:dkim-signature
         :dkim-signature;
        bh=TzOuBcrPobaTSTGj5mYQdHXaRmyMX9J7X9vHXTCyMF4=;
        fh=W/wdUqSzszhUqObx1oOzhwmC7DUf1tzLZQpkGhMREYo=;
        b=g57HmYW3CHpFcmiXTKGipbu34gQ70JQxUmGLk06CfNO3xtylGYvsVpnFcCLbf/QXYe
         +klNf57WktPB5g8bLiAKUVFAaajm+Tm9+6Nwjd9vhmGt9bhx9GPLDQ3phZbAcSbGsNh6
         83iQCu5uqRr6vc6fjN/jqspHO4z5GiSO0O9zNpHdRbvO48Lx1xMx3AWR1xHsa4LkuA5q
         KXiklCk/48rDsFB/Mzr6dAU2vCXLJdMGzzvyayQRU+6JRWyK+7+bn8CF9TRXIEfBap5T
         hw0h+ReTEwMJUydy7TShmGmUA6Img3q2rqyMaWwK0Amc5h0cAmfzBXAOUiLgM6eDH69l
         VtXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HiM20KZ2;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772737552; x=1773342352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TzOuBcrPobaTSTGj5mYQdHXaRmyMX9J7X9vHXTCyMF4=;
        b=Cpwg1kJqrBrAukOIE6IGPOyaYMMz9UAGhJfAT5r60AGNHA4jjCmEOZBAsGNtYQO7Me
         hFbMFBaHbY918YsFFJusoLq7V/CwMO4yAQU1Fb+UEuw5lV+LwSyu2ZkAr8pLnOdDs2Gj
         SOxUqkjdSHVwtszqLq1v3lNc1mFb9XtYqDUV2Uj02+AX+S6gM+q2PxhcU+RCtS3f//g1
         s0NhQoMUIFPfOyD1yHZ1FhJzKAoMyrMim9Vpcc9pif9JGVnI5AdvrOWRHxBn11m3X+pN
         nxezVmIPQIAtDhqMqA/80Dijh1qCBNG1YXT48cCAF6sN4fjp4S6N2qREx75BOFOtjpPW
         K/Nw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1772737552; x=1773342352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:mime-version
         :references:in-reply-to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TzOuBcrPobaTSTGj5mYQdHXaRmyMX9J7X9vHXTCyMF4=;
        b=PDXI/OsFgmui73SSTgR0g/tF1rx7NFYVQ1MdsixQfXWmYYD1qQ2zj47yNR3lcmJ0SD
         jYJyYl7mo0Wd9GDQ6sUR0xrc2A349/CcGUH5nf9CtebQVQJk9nm+fYNQds20DKoHSlGO
         J/jb4ILWhLQ8GhVkUKqdAD0LfzXkHt4irnuohvQn5h/KwFFmq03AvMab4NzEuHoMd0E9
         uYwbM1w5hdTumjL+hCoLXh+zpEej7FjfvJ+r/RwOaSHn7TiaOdvgvbow3uLOGqBQtkJO
         vTgpnhdAv+tvKKHyidLjsFshmMGyOecd0NnHhbFyYeodYgu+ShEn3VlWkxck95s80gOO
         hcbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772737552; x=1773342352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:mime-version:references:in-reply-to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TzOuBcrPobaTSTGj5mYQdHXaRmyMX9J7X9vHXTCyMF4=;
        b=Z5XgwWe1/l6idO6lCLDdTyw9FuSbrGMWT0ik9tMbQxu01cnKQvJqnJ9U2Hhp/n4a58
         9zEnMrSF+03xnlszNnI4429MWE5mMJiTZyEu23m+0fh6SgUHTiObfQ25CyZaNoeiKgf2
         Jb+ohbvtOCfnjROGhL/PqOTxPJf1zPDR9UPwBwBwzfTtIrM6cJvc2bRNqxO2fhuwZfWm
         +4Rz1nK2LMT84F+RAN5u8F3K4l8RP5sWOIr+4HPT+0R0G88AhTKlkjjv1nn1hgUmo79I
         Lg38r6gys9X1lseRdfLdGQJgB1kozyzz3MW4OzVKE1nPK67RwHbHpsXyPfWLbprpB9i2
         NtFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXRnAVTOV3j34IrWMPpfX/4Up0Yfv0onXMUrmoZa/+F/MCxabQDHPdEeT1aEJYfZigrlfOgOw==@lfdr.de
X-Gm-Message-State: AOJu0YxaytiyxRSEvyUK0Du/79NaDc7CjIp0yDBMHPsJx6Ne2QkqhPQJ
	GU3+QqnTRqGjYiq0jGYTOhmZQakvJLbxCVTwnyR7uOKf34ofUrzQ9zGv
X-Received: by 2002:a17:902:d486:b0:2ae:5ab4:f4c7 with SMTP id d9443c01a7336-2ae6a9ff1f4mr67958065ad.15.1772737551776;
        Thu, 05 Mar 2026 11:05:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EDLyaP71Vna75cC0j3ha5l4M+LAmVG1YD4SNmo2Knlew=="
Received: by 2002:a17:902:f60e:b0:2ae:4932:32da with SMTP id
 d9443c01a7336-2ae72ac5bfbls16212595ad.1.-pod-prod-03-us; Thu, 05 Mar 2026
 11:05:50 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVVW3GUsel2G39F4zOtv9tVKZUGh9YzibVgpfFdlLazB75K0gDHrQ8QDd1xFrIVJJaotUNycVmaxyQ=@googlegroups.com
X-Received: by 2002:a17:903:2f8b:b0:2ae:5104:571e with SMTP id d9443c01a7336-2ae6a9deed1mr60278665ad.9.1772737549902;
        Thu, 05 Mar 2026 11:05:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772737549; cv=pass;
        d=google.com; s=arc-20240605;
        b=E8Alx3oTedp5kasvk9ZRYPsQz7YO0T+OeqQnotcyYNHJegVGrcfuewcDgKnMuGK2r+
         Gt4+U4njWrsAkULrPkwQoneH96sP4T3Ud2sfZrHhMCPjJOxmQdAubrpG2q8Kb65nCXWd
         X5qeF4WnAxIONKDS3oUO7/5PqO8XgAtB1yxqp1pZxHatadtIloFvKVasRl4v/YlJBdQ4
         f2m+Xy43wLC56bijYEmSv4AJoBAVXcEdFI83QdP87ZNjxi8jJch9J+NtU3Rsqtdfo3Dd
         NchmJsupTjcKSMqrKtxKPxPoBE2fVSxFtxArLRy91K4Sz21BNn4vS4M1pdvqs4WEbhY9
         93ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=DUfdbW7OxfhKiR73pKbZr0uWEl4+qEzhZGOpiUb5qj8=;
        fh=GJEiC/6PJHtbq3uvcdri1ocD619aLJwdHlaCD0CRjQ0=;
        b=DkTucLiR62Tw+YdEUil7dw3EBXd3Fea0C7QHHLkj5veDdMUgUWYiCBWb1b8uNvBmCu
         PPlyfwqseZpUkJK6dGUWUo0nW9Mb7P5YQMraX68AKDLAYMUSDk8zlsd7weC3fgqF1KHv
         JUJXE3mjhjDexLRffMMvcQ3LxA2eVB1uWmPcHVWlilq0GhvMQCLG4pQQNfFY0Nah07+U
         HybkutZMp3NGs3qaZ5IoqsZd9lLyiPbmCsYADS0H/882tsXKNm3sEXjsNVfCnmRZKaMo
         hR6yM+00U54Vy4M2JsFG4zxENnooYO7o5LegzEl3gqhjjPTyE/OHIAq8dZpIJ1o+j1nd
         RwIw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HiM20KZ2;
       arc=pass (i=1);
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ae490e0e17si4727805ad.0.2026.03.05.11.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2026 11:05:49 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-7966d7b8226so3744437b3.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2026 11:05:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772737549; cv=none;
        d=google.com; s=arc-20240605;
        b=GoAqm6FPlctCPfMK4fY+dbW8vIJDo0X0YzdSfj/iVkpk+bTFGZK7h1Q0DfRy0oXGIU
         ynkOqrMMUthyY9C0W0nc2HQCw6NMPmueIAZh5AKvaA7GVHSle674JMJpZCfJtpfyL7Kh
         ivsftBnFJwNO1Z4ZmhMdOXBmz6kn8nQIrqnPPynarawvyEhltIjGBnEMfmwq2QMinKh4
         G4nTu7vpvokTrDokIkwVSIax3w57ix14+gu5d23bAaphlbuo4YeuzodZCuplqHDiu2Ts
         5AXNgYLcD93i54vDy+cemcyAcGJvt8obU/RrOicCdryTSif6jnuzYJXUC/Ez1ZfVzoEK
         xLnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:mime-version:references:in-reply-to
         :from:dkim-signature;
        bh=DUfdbW7OxfhKiR73pKbZr0uWEl4+qEzhZGOpiUb5qj8=;
        fh=GJEiC/6PJHtbq3uvcdri1ocD619aLJwdHlaCD0CRjQ0=;
        b=gvJxSj5cR27Ak7LQ8ooXGeXD4PeqnvholQUStZWRSYYv3ddXc88INnp0GOMnnOXMJB
         ovfDW1fHdASVdTxsYQqLWWalyoV9iqvZnP2zYIyLFLg2h6st69Ise4I5O+MVuJP0n6AT
         tJ5GU50KPjoPEPc/mjQZs1kS1SqrfK/IxFe+0/y14t5keQPkiwm+x5Vwj/f+Lseuz7uI
         dhDwPbkHzEK1kMCzcabsBIdpWwZrOy3d8SqTn17sr6m95zzkGvu/+RKA2RzIPoGD6IEh
         l9bV8ZhHejOQE4MHGBupmNRcHJrFO19xm1YLCyHUHXCjUzVD2m6FYbhb0T0KY9DX+Jke
         Q28A==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWdCoL3pXOgtfK8y8qNUqbOHcsCMgVHjWSmf+AuCfXowZSG7MMQlMsQM8uMGM9PO97u/XRx2IGGbbw=@googlegroups.com
X-Gm-Gg: ATEYQzxb7p/rhHt5xLE4gCJ+eF1Q2JOxKuDqd8VnwFe8kp9MAlbvOzrhLwkv2YqSt9i
	UVUt3C/hNJPmmsvFhK/nBRg1CxX6d1Dllh830/ZeaS49QZHtQYEw0aFV5SrNEUmjnhejrwLooXZ
	P2FDZ5kVnpEWbB2cdNwJE3GSPR/Dk/oC8vrF6noqVwQA6uohAyyu3i+stOnpFbh9notmW/gkWMV
	nzHcAwvynLk02LBCoqo6BuhidlCSOy0U5LI3RolHG5pcVJJj4Tz3ccWMKbDwS5RGKRxasIiz+Gt
	cCInYg==
X-Received: by 2002:a05:690c:e3ca:b0:798:1de:f894 with SMTP id
 00721157ae682-798c6c843e6mr49794737b3.4.1772737548885; Thu, 05 Mar 2026
 11:05:48 -0800 (PST)
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 5 Mar 2026 13:05:48 -0600
Received: from 95991385052 named unknown by gmailapi.google.com with HTTPREST;
 Thu, 5 Mar 2026 13:05:48 -0600
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <bd935d83b2fe3ddfedff052323a2b84e85061042.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me> <bd935d83b2fe3ddfedff052323a2b84e85061042.1770232424.git.m.wieczorretman@pm.me>
MIME-Version: 1.0
Date: Thu, 5 Mar 2026 13:05:48 -0600
X-Gm-Features: AaiRm51wLGHSZ9SaMaT4E-JYzg2vW23YHvcBblsyf-Lc9uQK9qhJFdTRUjtyx2g
Message-ID: <CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA@mail.gmail.com>
Subject: Re: [PATCH v10 01/13] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, 
	Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>
Cc: Samuel Holland <samuel.holland@sifive.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HiM20KZ2;       arc=pass
 (i=1);       spf=pass (google.com: domain of ryabinin.a.a@gmail.com
 designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: 1252A21736A
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCSL7B6LWYHBBD5IU7GQMGQEAYIJSJQ];
	RCVD_TLS_LAST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[pm.me,arm.com,kernel.org,lwn.net,google.com,gmail.com,linux-foundation.org,siemens.com];
	FREEMAIL_FROM(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[24];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-0.989];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[ryabininaa@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email,mail-pl1-x63e.google.com:rdns,mail-pl1-x63e.google.com:helo]
X-Rspamd-Action: no action

Maciej Wieczor-Retman <m.wieczorretman@pm.me> writes:

> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -558,6 +558,13 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
>  #error kasan_arch_is_ready only works in KASAN generic outline mode!
>  #endif
>
> +#ifndef arch_kasan_non_canonical_hook
> +static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
> +{
> +	return false;
> +}
> +#endif
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  void kasan_kunit_test_suite_start(void);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 62c01b4527eb..53152d148deb 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -642,10 +642,19 @@ void kasan_non_canonical_hook(unsigned long addr)
>  	const char *bug_type;
>
>  	/*
> -	 * All addresses that came as a result of the memory-to-shadow mapping
> -	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
> +	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
> +	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values. Thus,
> +	 * the possible shadow addresses (even for bogus pointers) belong to a
> +	 * single contiguous region that is the result of kasan_mem_to_shadow()
> +	 * applied to the whole address space.
>  	 */
> -	if (addr < KASAN_SHADOW_OFFSET)
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
> +			return;
> +	}
> +
> +	if (arch_kasan_non_canonical_hook(addr))
>  		return;
>

I've noticed that we currently classify bugs incorrectly in SW_TAGS
mode. I've sent the fix for it [1] :
 [1] https://lkml.kernel.org/r/20260305185659.20807-1-ryabinin.a.a@gmail.com

While at it, I was thinking whether we can make the logic above more
arch/mode agnotstic and without per-arch hooks, so I've ended up with
the following patch (it is on top of [1] fix).
I think it should work with any arch or mode and both with signed or
unsigned shifting.

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e804b1e1f886..1e4521b5ef14 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -640,12 +640,20 @@ void kasan_non_canonical_hook(unsigned long addr)
 {
 	unsigned long orig_addr, user_orig_addr;
 	const char *bug_type;
+	void *tagged_null = set_tag(NULL, KASAN_TAG_KERNEL);
+	void *tagged_addr = set_tag((void *)addr, KASAN_TAG_KERNEL);

 	/*
-	 * All addresses that came as a result of the memory-to-shadow mapping
-	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
+	 * Filter out addresses that cannot be shadow memory accesses generated
+	 * by the compiler.
+	 *
+	 * In SW_TAGS mode, when computing a shadow address, the compiler always
+	 * sets the kernel tag (some top bits) on the pointer *before* computing
+	 * the memory-to-shadow mapping. As a result, valid shadow addresses
+	 * are derived from tagged kernel pointers.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
+	if (tagged_addr < kasan_mem_to_shadow(tagged_null) ||
+	    tagged_addr > kasan_mem_to_shadow((void *)(~0ULL)))
 		return;

 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
@@ -670,7 +678,7 @@ void kasan_non_canonical_hook(unsigned long addr)
 	} else if (user_orig_addr < TASK_SIZE) {
 		bug_type = "probably user-memory-access";
 		orig_addr = user_orig_addr;
-	} else if (addr_in_shadow((void *)addr))
+	} else if (addr_in_shadow(tagged_addr))
 		bug_type = "probably wild-memory-access";
 	else
 		bug_type = "maybe wild-memory-access";
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAPAsAGxpHBqzppoKCrqvH0mfhEn6p0aEHR30ZifB3uv81v68EA%40mail.gmail.com.
