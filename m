Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTMT3P4QKGQECT72K4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9332B244DE6
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:45 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id x190sf2167532lff.17
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426125; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnrDE0PUMOXFE8WKpHEPnWLpmdQXwSAV1L2BDikskSjL9l4sYcwkmcX+Mud5wRR+sO
         nmTQy3eerteETcc8ce9W+vK6XtFd8/C3xchnQfsG2bfYRiPUuwEZbZhz4/J4U1+aSLJU
         NZZV9y0WsJ6oG3gDvs2JJ8/DhAXcYsMKnhtyxQ9qpAtLFT5IFhre0UBVlg1AX3hqCvnd
         1P/Opyi/pq2mi8yRLFBRsqfUzZHhRGOs7Qv+0aHjCgppFRW+C/p0f6J3QwyKNvaNjhUz
         IhHC4khuycDnKqZM02VqYARPHH1WPXWCJ8YhE3sDH8dadLrBk0o+7DsuETmtOwNSvYAZ
         TjHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fsVFeA+wQoOEA3ZPEHcsIe49ijxduyhWNZGfaXlEMG4=;
        b=KAGMKwrZWcxmjntne+s65L3Cnfi1bPGXZSm/9C4Jy4mThrkXuc8yMQUpth30xKMA9Q
         KTrOf/yJDFsXOG5nfFKJuIQ1LOMcFAGa/iAQea5fY4eNsOSXjugGi0KXJUkDj8qPb31i
         XyHv9/AN+2XwgYDrwrfdAkR2qcwHQ6a7bYQDDnHmMIE0woAT27Jr35MZ1G4UMcsde8Zd
         e0eAbpZNQu/EXhk4L2btVu/lWqN+SOiDWYizpplUsQErIRTK4En7ClFONrKrWaFHmfv7
         lNdTSgEnnxvfqK6+/jZ6yPpEFY+IInEw8vcrR+3Tjd0C51tlznWwXo2Tvd9lU/tGIGWL
         8cGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TXhmlUEH;
       spf=pass (google.com: domain of 3y8k2xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y8k2XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsVFeA+wQoOEA3ZPEHcsIe49ijxduyhWNZGfaXlEMG4=;
        b=TedrG3uFIVJnrn1gIrABGiQWyaJYFt/kJ7cz8THmOl4ri+2WiIe1dtYOlewA0OyxYh
         ZFSdOp+BtK8X2n9Abu90x+FchXeZ5zGAArYtMmVwBkABtf99LxLAO+qNHP1V6jgVwG3v
         pcxlVYUS+JhPsEXUxmMWNYERh1lpzh6HXhSnKBB5c4+oIgJbI1LGDktBJLpfYv30aPIg
         o/WhAYbcA9IB5mFSVVAfmSh1w2YZglZ3Z3BJg3eWN0abc3FC8lJq2Uk4/rs0eArCOGH8
         7ImOUFQvjS1wEUMnEl9hVrxSoSnJGRoZrtW3NnmjMuF/rHNjyeKA+JqS2JQMWQsVVcOm
         wf8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fsVFeA+wQoOEA3ZPEHcsIe49ijxduyhWNZGfaXlEMG4=;
        b=IU/x9b4tC1t0wjEq9UCDavHGnRMeYkH72QO2t83B6Y2XL021i2UmoTFZI8eaRXhP0h
         Vaz9uuq9JFzImul0lREVofRlGkPa4Ox6SNheJe8LJ3yHP7HFQwKMIHs3Dxcdn68L1rQg
         6bHsd2+aQKVCW8tDpaApDpskpfwt83WO4xw0LEwZ1cdHIjeD1TK8qqCPe76+o32vWXxe
         iGwDgTZiKKzs/7QJCI7xzbaZVu7Js5AgLXwJorrnlQ+Waq5RF0GYtie4+Ae6rt76+KIL
         C342DnqlZSpHX2xa2Z9NzEYof2dS8Q6w/iE53oPF3ERmRLfDrKwekEJYIw/b/PSxaSHM
         BoAg==
X-Gm-Message-State: AOAM532ctfgaPM1YnyDPuK9jbfQ0I2a113VlchXbwUl+x4Bw6q1T7rqh
	csAzwS+wfS1YBKs51VONvcI=
X-Google-Smtp-Source: ABdhPJzm0zggisTuqwiccKFAG5HvU86ThngIhb5QqnPe0xqatKzOvsqzo5pt5AqGZjPB56ErVJgF1Q==
X-Received: by 2002:a2e:844a:: with SMTP id u10mr1784193ljh.213.1597426125176;
        Fri, 14 Aug 2020 10:28:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c03:: with SMTP id x3ls169792ljc.5.gmail; Fri, 14 Aug
 2020 10:28:44 -0700 (PDT)
X-Received: by 2002:a2e:9c95:: with SMTP id x21mr1369415lji.96.1597426124470;
        Fri, 14 Aug 2020 10:28:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426124; cv=none;
        d=google.com; s=arc-20160816;
        b=sIR5fm0+Jc9zArOzcJI3iJc13k2wtmA8G5KODp3sBqazA/A5LKg4TlF+kpqVwxCJ4h
         xp0GXJ2a/j82yx+780dB2VxUXPwXLbTl2zO0waK5gVqjV7sauymEsW61AfceZ9xkcLKi
         DpHI9rujMwefkYAhKs+/Ek5j7BghMEt77n0n/nJKVH3cZuZI/YYEt3LboiWkJ8hNIPu8
         MHq0fyUgNwSnZwmoM0HgAlmkYzoAqk1Ec25VZCzyVAxrqVttviDzi/A8Rr0BAw3fK+KB
         HWyWoCeUp5NYPIWz40zAOEC1KMiY2qPgQ75hYBoN4XhNvDnx/1g7y1wXXsfR+GEEhwMk
         DkOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Pcjdii+vI+eVQZmrwdTthlIVK/0Kn69OYG7nvUYx2MA=;
        b=JbTZLJBZq4ZH/UqV0V1tkE5/xMNjiJSSu+AbKMkIfsT4bPVgP9IOaPqs7lc+6JY945
         XNOAx2K0dySi6xajypsNc+We2O7GjD+8WqCn4R5rnqGnzHShPD/y+/kKESqWXh4Rk7bn
         vEgKflnato+NGYz6JTcRMu5JIbnbQR0e3NyiMazmm+iVLzGE4vembfMyrVsjaRIv+AWz
         tWfWfOiz0jwRySOuMLpMOt2nmDnczxZOjQe+Hi4q2c5zT8WqVKkfcJ/f1lo4NDEivfud
         cMNAvbSoqzSIi+2ZcQCobP/4Qqo9pn0lJBAOtURSHMxZigeYKiX/x97HAOgldNuF3pln
         MxEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TXhmlUEH;
       spf=pass (google.com: domain of 3y8k2xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y8k2XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p12si404210ljj.0.2020.08.14.10.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y8k2xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c124so3434236wme.0
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:44 -0700 (PDT)
X-Received: by 2002:a1c:6083:: with SMTP id u125mr3397670wmb.161.1597426123818;
 Fri, 14 Aug 2020 10:28:43 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:16 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <8cea9310fa8d55775ec137e5df4d8bb654bc24fe.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 34/35] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TXhmlUEH;       spf=pass
 (google.com: domain of 3y8k2xwokctowjznaugjrhckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y8k2XwoKCToWjZnaugjrhckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 70a7880d5145..0d95d8391d0f 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -131,6 +131,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8cea9310fa8d55775ec137e5df4d8bb654bc24fe.1597425745.git.andreyknvl%40google.com.
