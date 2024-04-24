Return-Path: <kasan-dev+bncBCF5XGNWYQBRB4XFUSYQMGQEJ6LGBAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 10DB18B0FBB
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 18:27:32 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-3c84a6a9a31sf85740b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 09:27:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713976050; cv=pass;
        d=google.com; s=arc-20160816;
        b=oilXhmGMvmeEC7cJcnkwiyTCmbuhivtWDKZgx9tBWjh6iOxDjgO0ATpXl7zkUeJYLX
         YAzsffLvifIkXvye0SCdaN7x2oXd0vDfy+4u4nBpmjWkjDLvzgnkbLBJWJl5s0NWyPD5
         7rsXjCzxbNIlAkiGw1Ctnyk1x8fysBRBCdfWykrjstVyKi3WOLNMZGMOPJomvqqNCA8C
         qSJX+Ognxp6NbGrV1JUXPqMZlCEMTUajxqBTsn6ojrluCrBl3XkI04Uo9sPj4x6mOXti
         uCX3gDfAApogJQ+lUGMB07htT64v2lKZIpmiKqG5ccgUZfJxf20s2XSR9FAc4/Mitpoo
         3T8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9vkkBLylAZk4BSEAvOp1iY8Nsf0RIH2DSnDi4L+B+iw=;
        fh=Sv/t719svWLByCawsdxaodk65WY/XEhT+c+L5Jd4tko=;
        b=tHoqrvdvxzJc5HFVsVm0yIo+iGXtLswt/Mc0cLjeT9ZtHqGSvEb5Zs/0Vf/t+WAXJB
         U4MEnZVq11Mp1JLFAVqLpAAxB9eLkPPcDc7D0ugWz7UY9K/EP2u6jmYuMWvmhI9Pme6Z
         bHCmEWGSwjp2ivOU6luMPtINZkPZIgd3ZH5kyN9OFe5vt0uqUgvATeLEGmobbTXGRcqh
         Z/KrT9+XJJv30rm2Fx4hyVu/C6wO4N5eXZV3qVPRQdwJ1Qn/UsauSuzABO4ZnQd86Qza
         gf2ECSFLOZBl/KxTFy7VdjM0awqvOCC6uGfuGVeGxw37agSdoF4Ea3VeAUJiYXdzTjOF
         g4qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Gyz1LEYh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713976050; x=1714580850; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9vkkBLylAZk4BSEAvOp1iY8Nsf0RIH2DSnDi4L+B+iw=;
        b=CQdO+vKdpZyrMCsy8idpY4w8N4tuOqJ+vrd5SCdyDn88up2EP2E4xGmwccfdvGBkVf
         BRFEae06aJVLjfooGPci/LEmFkHgwkLrwrWi5iwHt+siuRTqUn4ukf7BbIRgL1kvOHNs
         0nQ6vL5r0fakAd/qCVzLUFM+uDDu43SwMqI07oeeJyotJVCFAhdMkFakcMt7FLl2oCv9
         tDg8SNFqW1M/wozYTmKwzeAawDyTirToZByWuMCeTp/L6qAgQ4ErLH60PfTI54zjU8lJ
         kiu7tS6xOTEK46D5dgEUK0B9SHgezCJ01F9s4nTTiV7Y6mD2zE1m0buQEjVpi7PLKT8z
         9asw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713976050; x=1714580850;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9vkkBLylAZk4BSEAvOp1iY8Nsf0RIH2DSnDi4L+B+iw=;
        b=Lul+ecLMPUKBMtBMW0jkjdTp88dZ9DcsJ+MLM8NbKf5whdo09YWr1tcxIzQoUoz7BQ
         Jywu19zf6nB4/fwny6s2/7G1SYAvo4dPcn8ODFFWxbzkAclcOvpEI9iUggjMQ95v7FGm
         dCiiFupTvBYmgaKVV00TAlqMpYOrKvo/dP9uKLdX1S4ZHwcLIJoADT21KP7rVfXdawTe
         sFgjJu3Rg2yJtDjOBQnyhXoZu5KHyq29FxwqDEkVxISQEB+Cya9bj5ksUw4WYfACU9uT
         O+CdAKzQ34ofWUa2IDZfhboULnar5eBbTr0ArYMLE1S+eexxjZxaTUwHh+GE+U50nmRz
         RkWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXVQulQfO+SBMg58Bbvt1q8s3Pmgwvjx+h1KuhDRZjgrfIY1l9HaGCKmL2Qvp2AQBpG2k+sSxFWExAoQDG6J00iOlBBPxing==
X-Gm-Message-State: AOJu0Yw1N6WWuAL4XfbsM+uzS4osgPu+0z+Hkszn1Us0Vvu6zLxSulRo
	D5TBx1Hdt1l+9xExvJiPtrZP52Ap7KG8ohfLh3/jO7FSRGtFU+uE
X-Google-Smtp-Source: AGHT+IHvS2QDjKI/E4tdIQmGGzBXR87UkUQjWApE+/YbLi/71V+hu/7euc6dFzLO9iJjm+soj/hbgA==
X-Received: by 2002:aca:1813:0:b0:3c7:2f77:a102 with SMTP id h19-20020aca1813000000b003c72f77a102mr2637859oih.26.1713976050571;
        Wed, 24 Apr 2024 09:27:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c4b:0:b0:69b:197a:3a87 with SMTP id 6a1803df08f44-6a09c65ca17ls1549486d6.2.-pod-prod-01-us;
 Wed, 24 Apr 2024 09:27:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyX+X0qeCvP2QfFLR8ZSToX44GNhlJtqJ0srLoBOmdEb/TMX4J0f0KtrcgmxMaSUa9VwqW9Niln4o7K36VqaMIc+U1Q+d73WbU5w==
X-Received: by 2002:a05:6122:2508:b0:4d3:3f2b:dc63 with SMTP id cl8-20020a056122250800b004d33f2bdc63mr3466016vkb.5.1713976049622;
        Wed, 24 Apr 2024 09:27:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713976049; cv=none;
        d=google.com; s=arc-20160816;
        b=BsT3z9+vfLdgKAlGzGn4Vy01KfiqdSow3tu1MDEX3Xtx3EaC2zLXN4jlzEZnjoLFJm
         BaBrf4nQbasKFJLpvAIllnz+1bBhAfLS1wE8B+wOC1SJqPjvwoM3qhkxPtbQ8toPFJhF
         af1mLnlEUAWp5kbx7m8wXcoohXpHDpYxyC7jiSF08q14r7UGnZiyF9TX1yGmDpAaCIIH
         zNfWpPPINzp/aijeUExxWzp3iktQ6LNaEGFUwzYoEuEUJvxGmg5gJMP+6PvI4QLrEO4V
         Gviq7UrGd+oko9sqHv7Xlx+U+JtuTbcAkJBPUD4eGhPYdKicQBCp6PpuvoykAmkE5mIn
         ofCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=VqVdIKh+FGhuAkF80diaGZNWgnSMw4HuAlHZ0aOXJaQ=;
        fh=97ZcjfB8dswz69/gXrau7Ds7tJ4sPlwrQCKJ965YocU=;
        b=zkmB9Y1pNFN5WPxTP8U3ws3U9QohxwnHz//w1jz4DTyO4O1oT5DL3a9EUu61NESImJ
         myachtAIDA+4NkNuybdd4OtBwqCWzTqctM1gLNgl25p1RBWewKpWvL1PxPvQ9imxm8P/
         F23hchO+ih/mW5KkRQFapk5kODCi/uk3rLFVqxcd7vdF76vYMb28X+0chHv5GFX++Ezd
         kz7n3EjRPVPwJLL5jq1XIfqyzS02AS9SzEJtfMwDIfHL1IyXx0PAu+qO8UuPTSsHNNPy
         91tOWqFT7MpZNqzK9SZHxQzaeoVvOZ+/kjpt/VWT/fbVL5dIw88bUcMdEh+BybAkfct8
         hmcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Gyz1LEYh;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id o4-20020a1fd704000000b004dcb1b2f109si1362208vkg.3.2024.04.24.09.27.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Apr 2024 09:27:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-6eff9dc1821so78403b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Apr 2024 09:27:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUR7thDiqra6An8LWHjOe9jl1ihVsa47dHwjSLsbTnjMojlTRr8fzKXkcq7pHUFX1bCcgXYQSEGPlUiO8GW9EbZE86m8/WqXb7lA==
X-Received: by 2002:a05:6a20:96c3:b0:1aa:59ff:5902 with SMTP id hq3-20020a056a2096c300b001aa59ff5902mr2898404pzc.9.1713976048655;
        Wed, 24 Apr 2024 09:27:28 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id bq15-20020a056a02044f00b005f806498270sm7830151pgb.9.2024.04.24.09.27.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 09:27:27 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] MAINTAINERS: Add ubsan.h to the UBSAN section
Date: Wed, 24 Apr 2024 09:27:25 -0700
Message-Id: <20240424162722.work.576-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=707; i=keescook@chromium.org;
 h=from:subject:message-id; bh=RUQFXdH8cHsUkS7WjlnySjXvh+xuWtYB5a0k0jg62aQ=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmKTLtBpO5sGKQbNTQQhxZ0ZsYqUs12l6Ughw85
 8Dyfzf7pCWJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZiky7QAKCRCJcvTf3G3A
 JoKXD/4pxNwOoTftHBpfo2Stn6qEj5ph8TjzUq5xw0sAvUVgJmxp7K702EyccN/XySiLP+3ZEmm
 9RutTYSsj8CcQBjVrhOLb/xvlrEJaIspTh2p9EHB8piS8HHt6lpQE4YxgkeBiy7tas5vedCTzXa
 1a+mb8j5zAyqx3nIcOVe+QbaQuQob4txxHUJZ/OFqTgCnpZQdi9IFSR2k5ILVhYuoBqyF01ESCI
 1Osrm+i3pe257pYqItAU7opFf1pPETUEUoK/yCZ8oriu7XtP5WSovuV/aBZiCxemqQdqq6FmCOJ
 Yirj9oYJvuhXNEfkyi1N9RNTYWAyAfNuULtzx8BHLDMjtX4AKL31AYH4O/2DqoFb/3y1BWZyKBd
 cppLw0sEN52uyp84/RCvPiapZ7/M5JZbRbdoS7LKI0WQ9DdZsUVB0XJ8t9ckg3gaIGCbyRJmsQ2
 d7krynFko65NOjKREmXj2tWd9ajjgJAY6ASIurcHDqVhUjdbfcCSYjheAlDGbljc3pzaUPWvMdZ
 Iwyt3rCA32x51eV2YP4S7q9XgtONVibEmpI+uCnxfi/c6iReQpCHB2XmiLbIDLdkNo3TDyS0YA9
 S56kXblKN0pe2kQ7dvOsEd/FZzu6Nfn9CChe27WtPhDE6e1v9tVB/qxQOCIx6tHLFHvAYKafkbH
 mZ80ao2M K1vthAg==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Gyz1LEYh;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

The "ubsan.h" file was missed in the creation of the UBSAN section. Add
it.

Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 MAINTAINERS | 1 +
 1 file changed, 1 insertion(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 7c121493f43d..5acac5887889 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -22653,6 +22653,7 @@ F:	include/linux/ubsan.h
 F:	lib/Kconfig.ubsan
 F:	lib/test_ubsan.c
 F:	lib/ubsan.c
+F:	lib/ubsan.h
 F:	scripts/Makefile.ubsan
 K:	\bARCH_HAS_UBSAN\b
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240424162722.work.576-kees%40kernel.org.
