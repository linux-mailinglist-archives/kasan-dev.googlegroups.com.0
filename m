Return-Path: <kasan-dev+bncBD3ZDPGUYQDRBSOUZ2XQMGQEPYFXJIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1037487C755
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 02:54:20 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-29deeb2fc13sf303071a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Mar 2024 18:54:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710467658; cv=pass;
        d=google.com; s=arc-20160816;
        b=QeBqoqKnQRw+PJ0yVauxidFXW0EGojkj03rsDAS7BH0K8lJkzEH6FhB/7I6nN8zqXC
         B1vbbYh8b05bzqnZff+8aNM5KJLDBY2anj/NWi2NgVo8YwkkbHV8WyxMQg4TwjqIqqTL
         RElDFTPzYlIVUZpOgud1csfUGYxO4GqHoZpHECaEQ5pQ1PkANjo9zfOhhfyPMbWo5RSo
         xD+BW9OOnTj2ljgc50gQpbg6ZtI120AghGJsNgHWwPrvJRBRJmMnz6p/k6vz1+YwyfyL
         Id3G1O7qSN8G2T6gqkI+6IN9pNFLHB7VRkwVgztDgm+x0xVynTB8GnXXOMkqDT/5eTXR
         zHiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=I4Mwz0ehHaZZtc+jlVAK23YEFQALUhx8bdloSKwil2Y=;
        fh=Pav4M1bsKrNc71VgqgQh2NdHUsLiHYBHuAxMLz78Fro=;
        b=tS1gSDW2Sxn0xnYvvubtk5EtTTqOaOWqzPCx6C4ddzyw9t+pGFu5+WAOJ/F68YnNrP
         0JpWk0cXCESzcl0tpVfMaE7XWl8zkTwoL49BMPWqBfjGtmH9jpfPsieMRnhu+orFc3yD
         gx09V7zw2uYJjOlU4kJ9Pq12wmEyU+cWrPajIUYbtuUiFTe+3ia2R2+ZNj4kx3C0Sj2K
         6//UdCsTLh4fSIG4AHwkNgBezbHvTlXtDrAgvaQSzq7MwuLxginuyY4q7DKqToFpNRg9
         I1Mg6fDaKQGAUeIW6HSggT04WC0qDFh5tN/7rmq4WCH/W8e+VkQHrdrNAd8pF5R1gm2d
         qzVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b="U6Bi/ROI";
       spf=pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.90.199.7 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710467658; x=1711072458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I4Mwz0ehHaZZtc+jlVAK23YEFQALUhx8bdloSKwil2Y=;
        b=YwkXOnxZM6bfvOw2dioEUnL73cPDiUP3p5MiHg20FuyA9c1/9ChXFQwiCwVJjoOta3
         zTt1Wn5iBNuS9eM4SXTuKOYF4rZNY9tUnc7XK3ldJtlYz2UU2DcuaYli2BvVgLug6vTE
         hHF9HiKEJNP1+hYCCzZCwB2B5cV06O/jfgQX5xtEnMIYjy4+Aova3vA2OH0dG0K0NVBg
         Aw74SSytPisK7MbWg4htMDtnTdMx0fnaRc6Qvn/DO8Lp+ptJePXIGudjvl30Efs/C2P+
         0yJEXnq1cJhhbn/XRWQpFSzaPpXgv+dLgLTvFEnopaqxS0u8M5+FDJDKcZY4SwtvQW3T
         +gfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710467658; x=1711072458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I4Mwz0ehHaZZtc+jlVAK23YEFQALUhx8bdloSKwil2Y=;
        b=Czk3s7iw9BLTLtDLj4DfEF/+qQlraBMayhYt6O5EzBsVqo/YViJTIecD4izQWwL6Fy
         G7ahaAAcexkZtNcBReiKvNJ7txW0s414U/pgUuwTnrumCDmoe7rOyYp8XTILdHKwZYnI
         CQMr/Do1rSpty38lzZ3PPVRoQwRMCAtDHgkarieqd4slmiRRsPjdIfLkxnQoaq6bsC0A
         fzGmVc9vpr+4kZ/EQKDYyhZUJisVAWQgjMdRm2K4xI7DnqVJWIbHp6Tm7SAEHUgSYefE
         tuLLxQIp65sLl1eZ5LzlomiZbyOvkKdPMGoGl8Xg6fSUo+4lviP+9/gl1ZTVlwA9Iyxr
         oKPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdTwDHf9PmHXUXPPSm+4/HAa5LOFcTC9pNEGbEwz5deHrO4wtCwMEk9kMIDLYz0MWei1zxKh2IzG01/QuubSKou/uhYtGdKA==
X-Gm-Message-State: AOJu0YzUoOMGPHh8WvobolluUxraX/8XLY3vhexp4rCqEkWUAxw+dP54
	Iq7f+yH4ZghJX3n5xMmZPKZxTfB5HhD8q9aVua4CzPRCHQXRAP5vyuw=
X-Google-Smtp-Source: AGHT+IHnfAUH65UCGvpwi4OVVjt6LcOz8MaVNs4KNp7tDRFkqtYJ1AmrOUtGOWaJIMXzyPbjBpKPbg==
X-Received: by 2002:a17:90a:71c9:b0:29b:c47a:24c7 with SMTP id m9-20020a17090a71c900b0029bc47a24c7mr1647054pjs.27.1710467658033;
        Thu, 14 Mar 2024 18:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b101:b0:29b:c1c1:aecb with SMTP id
 z1-20020a17090ab10100b0029bc1c1aecbls597624pjq.2.-pod-prod-04-us; Thu, 14 Mar
 2024 18:54:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFA03+L0fSQg6rmwpypYYX788Qhb7C9tTdDfaobAGqjbSJARlWqfJm8gRGpKHcXmvp3XNoKIdTNkT2UcJdJe2TubapmHBjnbamhw==
X-Received: by 2002:a17:90b:fc1:b0:29b:af87:1e82 with SMTP id gd1-20020a17090b0fc100b0029baf871e82mr1738616pjb.48.1710467656660;
        Thu, 14 Mar 2024 18:54:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710467656; cv=none;
        d=google.com; s=arc-20160816;
        b=y6/ZoSG7Hxw2nZNJDHw3NwhEkATVO2EdxGPugnHPDY6b8bHI3aOXCywK0yopJzVH8O
         zUhnNIYJTHfZW2nxoHj5PHp6P5URxm4QYZvdmNOrcOu7QSV5DFZFKkn8Uc+o6do4Ve3X
         2OsSLMMHLQ4UCrigMfs4zIC+t310RBmj3iNNnGpLs0mcNPbKEbOsAL55LZwbqumrxvrE
         pWIvQEtj77vSPnLlLNhchYZhq+kgiViMR+5iHaBttfiORvePA/j1xqPkJCfZE53nEl3a
         +EuEmUSIoS/sfup1mdIpbXudAHt9wkcmevmf+CcofefnKEvl5csj47bgoSdaeDH8T1gq
         Ni7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=px9N44gO4i927LMckVeMvo+Wb1vg+vgE8QfX2H4P0og=;
        fh=bF0Vz+ObgSb73s1sdVuPzrZLifb1cWEnKoaFyKaFWf4=;
        b=ZgxJpDzP8wTXcxaKx9/Yr9Evcz2Gyie8FADEs7gvHTaB0udkFOZTf/sEqu+/g+qzmi
         CT1bNS4llo7SnEwn+aBUWxq6zMXm8R7esvdBPNBsm3zD2RovVGxbNxw9EJcbuYrpuKC0
         7BT//7J00g57gCnW02sGsolMlXUo7lLUyXX2TVLIsX3O0GgfyYKy3oSfFqwNr2zDmjhQ
         nZ9X+yRHrb+nJbu9wf66uNbZTDcL8yf7LLw4ZzrogFMHT/NzbAY9h9jOp1wwpf9T9Pd4
         jDfqcSkqg9MRHoQAh9kRgWhexWA+FLJcZspBT7xwZAKCX2z7QTtZn3C2pNv4D3gJwR9X
         10hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b="U6Bi/ROI";
       spf=pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.90.199.7 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out199-7.us.a.mail.aliyun.com (out199-7.us.a.mail.aliyun.com. [47.90.199.7])
        by gmr-mx.google.com with ESMTPS id b15-20020a17090a10cf00b0029be0aa6743si292978pje.2.2024.03.14.18.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Mar 2024 18:54:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of jiapeng.chong@linux.alibaba.com designates 47.90.199.7 as permitted sender) client-ip=47.90.199.7;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R161e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=ay29a033018045170;MF=jiapeng.chong@linux.alibaba.com;NM=1;PH=DS;RN=10;SR=0;TI=SMTPD_---0W2UCwML_1710467629;
Received: from localhost(mailfrom:jiapeng.chong@linux.alibaba.com fp:SMTPD_---0W2UCwML_1710467629)
          by smtp.aliyun-inc.com;
          Fri, 15 Mar 2024 09:54:00 +0800
From: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
To: keescook@chromium.org
Cc: elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Jiapeng Chong <jiapeng.chong@linux.alibaba.com>,
	Abaci Robot <abaci@linux.alibaba.com>
Subject: [PATCH] ubsan: Remove unused function
Date: Fri, 15 Mar 2024 09:53:47 +0800
Message-Id: <20240315015347.2259-1-jiapeng.chong@linux.alibaba.com>
X-Mailer: git-send-email 2.20.1.7.g153144c
MIME-Version: 1.0
X-Original-Sender: jiapeng.chong@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b="U6Bi/ROI";
       spf=pass (google.com: domain of jiapeng.chong@linux.alibaba.com
 designates 47.90.199.7 as permitted sender) smtp.mailfrom=jiapeng.chong@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
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

The function are defined in the test_ubsan.c file, but not called
elsewhere, so delete the unused function.

lib/test_ubsan.c:137:28: warning: unused variable 'skip_ubsan_array'.

Reported-by: Abaci Robot <abaci@linux.alibaba.com>
Closes: https://bugzilla.openanolis.cn/show_bug.cgi?id=8541
Signed-off-by: Jiapeng Chong <jiapeng.chong@linux.alibaba.com>
---
 lib/test_ubsan.c | 5 -----
 1 file changed, 5 deletions(-)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 276c12140ee2..be335a93224f 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -133,11 +133,6 @@ static const test_ubsan_fp test_ubsan_array[] = {
 	test_ubsan_misaligned_access,
 };
 
-/* Excluded because they Oops the module. */
-static const test_ubsan_fp skip_ubsan_array[] = {
-	test_ubsan_divrem_overflow,
-};
-
 static int __init test_ubsan_init(void)
 {
 	unsigned int i;
-- 
2.20.1.7.g153144c

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240315015347.2259-1-jiapeng.chong%40linux.alibaba.com.
