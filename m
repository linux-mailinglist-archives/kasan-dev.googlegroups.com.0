Return-Path: <kasan-dev+bncBDUPB6PW4UKRBTPQQGAQMGQEERTWMYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 72D8A31285B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 00:31:26 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id s4sf10788122ilt.21
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Feb 2021 15:31:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612740685; cv=pass;
        d=google.com; s=arc-20160816;
        b=l84yQpEXFz3fsBnOX1v1y97RafobGITaiGD6afcnW5kvFAOZ7E1oBjJCrSzdMKrd1w
         PxivF1USYwea3H9kYMRXzBU9HML9+GKNoMu1tODa5rd5qrl93xCIYs7tYgMP9EQ/K6uG
         N9r3ZJ0p/e98iQz9rUIibOp99TgLvnhXCKojvgh3rmN7pM68OQA2tv7pfO6frBIGuWq/
         1NmpZGwPwAe0XISSraRhYpZyCnMaxG8dV1S7oD/15L4N0L8oYE6MYfTBX8KTiGzbi8cx
         BVoZgETIGLJVCWMHL0MIJcwqbXNyQ/qkQ1d9LRBMOgxj0/qqldU6n00p9k+U2RPSufYQ
         Mrfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:dkim-signature:dkim-signature;
        bh=vVcitYeB9FoKRZ6Epm+YkmjjxZhE5eY1WqSF9Xxf5R4=;
        b=Ex3kA9OXgUGB3/UkjpGpVIKd24kHRc1jbcllO0UwOoWasyfkwWcHgXO3jfVzsdx7vQ
         mqeUj0KZcuS8bVObbGaE4HMhQExHd0VdDsjf3aDRajvaHYraWYYUrKzQ+kEuypU38qYl
         Gbw6L6x3EA0NKMCirnocJXzgj0hkOY7OeKKlopEMkuL5K1WQnQRk0bhg4HR0oPDjIvwa
         oEOL0myjjYVK5eYJmSIGZnVbi5at8Xhi20V2mUR4rAB4jdKADO3XwSt13h+A8pC9SLNC
         mnUxrUoF5pGta0gfXfXHrs2Zn98r3aDVS6nEOmiLf9bmMdObeCCYEra6QvoJEtKI/Ew1
         fHsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oaXRUPA2;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vVcitYeB9FoKRZ6Epm+YkmjjxZhE5eY1WqSF9Xxf5R4=;
        b=GPaLkfbIbHe0LpkcQurcTrRZmUHbFb1wxfEXtfWGrr4sBwQeMUdK/zjQq/3gNVMft0
         qcj6PtWLZkFUCXcSjTWuZOCnFhhYhCBCpfxNPFh4J1YZuAilIJsJ9zzf/fy5RuDlogHu
         atxsgzVRtwoI0kdneyH1mhoSPqQ3aL5uf/uLxN0/+6QaUvXjWW9UX47gO1gytPCzZvmv
         Rv13Bwv5G2hrVt70ermpOFTkNo2fQUXQb1m1j89ALUsB7DBb8Us6Poa3Ah/IkFnFVQI5
         65vgi2ddaRCPdZhnfxksYjhwjrBZvLjS6t2NVDPdS8w1XzJ0Podx2BKO62Mr9kNnYvVu
         rg2g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vVcitYeB9FoKRZ6Epm+YkmjjxZhE5eY1WqSF9Xxf5R4=;
        b=M5pqzwF5uL1tpTlVZsiXlfT18qaQotxMN0vhzRC5wWmVV9/NI0gnPzRuAAXH3dggxa
         tDOU+KyIyDcmhURrdzQMTlxr9UFvIF/q8Sl7yqQL1L8yK660KWxe06sOzTldh2W6HS/K
         DrbokcN0+zFJZZPCVSOR7TOtycDkYVNFhF+ohR/cOyvFQAyXHP+7EZCD8cWyd4dhRvxk
         2XsY9bL8Fu8GkSU3L48NxgQFe4UqpCfQH4/mWda3aho4BW6/2+Z4AAGowmRGdWIO4tD3
         3axBKkROQihxVE3CqFY6umzBN3OkA35B009OsEkHtcyCnW2qJGIGaKdWi6zARdWS3TIm
         Vo2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vVcitYeB9FoKRZ6Epm+YkmjjxZhE5eY1WqSF9Xxf5R4=;
        b=fPnJABt3igdmKNE15PjjekTXt+a/3VRhrhrptIRELDy4RP5WcGqrQ4EjuiTj7QWKNO
         SApW4JAUPFRvH71CU2+YTg7eqeRlMaH10STV2DJ9YeFOcJcNBr9z2ur6Nat8iFEijni4
         pC1V2+yJGOEBDDJWTYlya8xWg2lLmJKTv5gS5H01nuyKikAMU7YXiCTyJXm2q6ymqd4j
         84Tl/dDCjCNw9IEVDxmMYFzeJ8AmIUA9W8DyEfqijYf9IYvFS75KLIPmics/KXKKMKM1
         kH1z8vRDwonHd3NN4TT+zJWNsHx6NechAuWX6kG/3/DjiG3/PDcD1z/nJik1r2WIWoM0
         Es9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531B9CW1kWsMdY8xQocFdoDj8LBKjeM61xlTjzOQoWJRb5UTY8hb
	93DFw1T1TMbZ09LAglQUBOc=
X-Google-Smtp-Source: ABdhPJy3sCbuLYYG/+kQ6RmPzwaRWoKrcW0qDSVDP9LTuoMVvIpIXJB0A5Ec+5+uvMnPL2P1PL9+Mw==
X-Received: by 2002:a05:6602:234f:: with SMTP id r15mr13306116iot.100.1612740685489;
        Sun, 07 Feb 2021 15:31:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4aa:: with SMTP id e10ls3624578ils.2.gmail; Sun, 07
 Feb 2021 15:31:25 -0800 (PST)
X-Received: by 2002:a92:de4b:: with SMTP id e11mr12566581ilr.123.1612740685075;
        Sun, 07 Feb 2021 15:31:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612740685; cv=none;
        d=google.com; s=arc-20160816;
        b=ATuy6L87/qDJBchef0oYQZ5kPNBYysSyq2ZhGmjUVJKi0lSpfOjCvIJuUoSMQtU6H/
         wbhc90VhDNrno7AAxIU4qaMk5yNaDysRBz9ZC2QE2VYS0casz4M2Xsl6ELSm7XqxRfQG
         Rmak1ek5QRV+4BIvwODbDv8ZU4lwN0r+tM93CN5QXnumXy2J0acadDf2J07Q/RSefvtV
         1mLM3x/Y/RDaVt13jHVYBQGUY8hzYdMPIfWI9pjwlJijfxuZ86sKmqf022Jo4lDpUoiW
         3yGY6ko4hbXR1a1C6TVlZ5isT4qwqoqsN8YBiIf7N0Vk+2Jcw37t0E7MxdhPBPTM8Z9j
         fzxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=o5IhRHEGMqXqh+QGBqGS9tIVGn7/L64cLJSFPIY/AWc=;
        b=wGwnkBy0R3cpE+Esg0tItrTfkCQVuuAMkCaZgkLNz3h3vJUBJHb0gB49XiN2/AIF6t
         xaWPn8zmDG0SCnbRTOg+fTMi7hj+I7FFnI2Z9hcGhvSTV+i7t31B3lZvn7hiihRNU1Nm
         pc/JPSJ6FQ4FN78V8XDl+J1PML4hcp34UlFdxbh/GkgJoAKpTnDPyt/gLjY2mlEvESZe
         tI/6ZoYOAI5pcD1rOozR0Y+O83MDof5xZJoTCvCpsfKWNS7o/0kuKGuMpVG4XRQ8g6Wh
         oTBneDOpbs0gPU5pUf8yYJoM3gr/IRdq988XZIP/di7wJjPwGrXQK9HVC/1pXXh4EBGv
         EW0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oaXRUPA2;
       spf=pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=achirvasub@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id v81si668571iod.4.2021.02.07.15.31.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Feb 2021 15:31:25 -0800 (PST)
Received-SPF: pass (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id o193so3254867qke.11
        for <kasan-dev@googlegroups.com>; Sun, 07 Feb 2021 15:31:25 -0800 (PST)
X-Received: by 2002:a37:a58d:: with SMTP id o135mr14012949qke.204.1612740684640;
        Sun, 07 Feb 2021 15:31:24 -0800 (PST)
Received: from arch-chirva.localdomain (pool-68-133-6-116.bflony.fios.verizon.net. [68.133.6.116])
        by smtp.gmail.com with ESMTPSA id 12sm15494228qkg.39.2021.02.07.15.31.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 Feb 2021 15:31:24 -0800 (PST)
Date: Sun, 7 Feb 2021 18:31:22 -0500
From: Stuart Little <achirvasub@gmail.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Arnd Bergmann <arnd@arndb.de>
Cc: linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: PROBLEM: 5.11.0-rc7 fails to =?utf-8?Q?com?=
 =?utf-8?Q?pile_with_error=3A_=E2=80=98-mindirect-branch=E2=80=99_and_?=
 =?utf-8?B?4oCYLWZjZi1wcm90ZWN0aW9u4oCZ?= are not compatible
Message-ID: <YCB4Sgk5g5B2Nu09@arch-chirva.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: achirvasub@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=oaXRUPA2;       spf=pass
 (google.com: domain of achirvasub@gmail.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=achirvasub@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

I am trying to compile on an x86_64 host for a 32-bit system; my config is =
at

https://termbin.com/v8jl

I am getting numerous errors of the form

./include/linux/kasan-checks.h:17:1: error: =E2=80=98-mindirect-branch=E2=
=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

and

./include/linux/kcsan-checks.h:143:6: error: =E2=80=98-mindirect-branch=E2=
=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

and

./arch/x86/include/asm/arch_hweight.h:16:1: error: =E2=80=98-mindirect-bran=
ch=E2=80=99 and =E2=80=98-fcf-protection=E2=80=99 are not compatible

(those include files indicated whom I should add to this list; apologies if=
 this reaches you in error).

The full log of the build is at

https://termbin.com/wbgs

---

5.11.0-rc6 built fine last week on this same setup.=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YCB4Sgk5g5B2Nu09%40arch-chirva.localdomain.
