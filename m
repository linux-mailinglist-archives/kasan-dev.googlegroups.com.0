Return-Path: <kasan-dev+bncBDAOJ6534YNBBA6Q6XBAMGQETB2JRRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98D2CAEA293
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 17:32:23 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32b48369fadsf10420791fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 08:32:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750951940; cv=pass;
        d=google.com; s=arc-20240605;
        b=jwK2pPTcqYCIJfh1YhuMvYE7WeGUVQwdLzjX7B+7+SGxngxgjqvwiSpEVz6BouWBlL
         VjcPG1xXYIxbC21PViMqRRXyp62Lv6N+LjbmroPZ673Dryl2EbwsDEmyg+iEvtbwE49h
         c2MB5NdAMju7hG5Jkh68wEu/sJoTUwYoJNfrBa3z7M7sbvPVSZE0Lb8FCEU0jlPHvUl+
         Q9x247omr/JOKw8JsQwPNbW8gVKSv8+so/O0Ox7FkrhBQ+7Sm5dMdSx57Jdx0O0h2m+N
         CGEa2Bh2pqPnPXvh9Am9mrlWpbYiqpoeblV3BxvX+KPHAwQX8mZKLtuEK4BsYnTDuhty
         WxFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=3pUHG0td6HSBJhXjf/phsGZAvHQ7A+wu1JSdcqf8/7U=;
        fh=XykOY/UC+0DtH4pZCX681wFdKRjAQ34Q8VJmdgL30LY=;
        b=Drov+Jg7E+J/MV5qT/3sTKloKO/k2BcRupN5kb/jV/PLI2HcMQNaLrV1CRkkg+fKcH
         caLk7OsrqYsPYJuq5IM3zSuBX7FnzNLOTgLM0nAINrYWIV4qvQO1QeoU0wPBw1cC3uZH
         GynZzlBwwgaPOeq4LPyw61GfYU2o1Vx8KvIYtzJONnVM9slmB9eHfdwCqqkbGQxjAPpG
         +aJy3CkUE+DUGT/fmUduKmRddIbIhq4UkJX484IK4SOo1Lqtm6HqnMBgZUlB/mjmFqMl
         lWRcxyMFGx6FXf39o6akGZ9DfukcoVt631BYqDoqRz5/YFphiVnNlByEhN4gNgzLwtt8
         Dipg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ejIto/+/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750951940; x=1751556740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3pUHG0td6HSBJhXjf/phsGZAvHQ7A+wu1JSdcqf8/7U=;
        b=SPoV9sR3MEJFuPs8b5d5ajndgEpXxquFpLUFZhZrG3Sw/nB4YjKZ0lr55FkSxtqLjE
         cgtMUhfy7f4DAEkH0qGXhbNQYwT3fiZAwucckauaZRltOSGfuQ0AelR8qT8IASQV5ERK
         wIBtn70t+GUg4C22c5Q//+K341SQBZC82LMPQrRc8GFRfcZRf/6WzHIwgFs7XFLp2/ON
         C4qTM8mYu3g8j4igvDTtxjqZCM9RsWYurHwpzWCoC2tL33ZnES+GbwiLuMNpedUi4OSA
         jjgnN9wA3tY20JjNxrp9ys9Fu0Rm2iVKnGnzK3cvdcE7t9Vu+Lqr6Wc0Ls2krkVvka0I
         uR5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750951940; x=1751556740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=3pUHG0td6HSBJhXjf/phsGZAvHQ7A+wu1JSdcqf8/7U=;
        b=kDy8/hsUJTCNc41vPOuyECJYkKszW/QHlQC8eD2fsWxYl+Pjhmccy7j0QVzqS1QGZl
         BRbYbWH8BIHqFgV4FtC/r1pJp7+WEohOwjhY7t/GYcDu7T93pxb2wJftJCMQzL/dZa8A
         xZSFbFI1PDlCzolPjgih+HDYOGpOAUbc1nqFjQaGDyAnvYjwty/M3Ml+9fO82iT/uTdm
         wj0Su1WyyexfusDKtZuqIy08TSBA+6Z4haGKcg6OhDzROnE0CITpGtA5xCmtqO10KqqC
         zkZRcb2uPAYELLqmr9ilKEV3IjjCD6WQyGgiiNNl5wjyeR1ZOkylXvlWfza1yTIKT+aq
         tP+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750951940; x=1751556740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3pUHG0td6HSBJhXjf/phsGZAvHQ7A+wu1JSdcqf8/7U=;
        b=RGYtJ84+BIxuwYfcNwdc9fqOoKDH14k2ket2oIM5+S/rQSvz6nlYOrWNoB4S6qmY9A
         LOuuGlLpRM26vXBJe/HMhfm3OZbWtp79EuQWAVJ+ekhQedEU5QMZWOUMfu9uw4RZthTJ
         HhaTte6sWdQQ0rBQJdPzuNDYjji3mrUKvJokKn9/r2Utc9xO7vdJe8DSxf92KUYlfUuR
         ThyEj07OfdmTWoIyG/4oeOiTXP+GULblzlWdh2LIU+/ML2NmLnBuQdpKB85ojKpRacq6
         CVl/JPpNCr3F6rRYosqQ2MGFsprjXgTaLMv8ijkOQbijtc5BD882s9q5lKUJK0MRyKYJ
         lmIg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6YEt4+XGBaKJpK6JTqmoabxWBqdOWGK98gSjsAotNXSzW7ghu1VtfdSLjr0l3rT2hS14nqQ==@lfdr.de
X-Gm-Message-State: AOJu0YxvmEz6nwk/3/FNFwmXrCMveuzhN6hRQZa5erwPrzQrEFiZwX/a
	zi/D+rY/o7SodueUKeaHmFwAy2Mi/nRJlKVzltCfGHH3YojpiUhCVF8N
X-Google-Smtp-Source: AGHT+IEx6UHOXmkl0xfRGCvQldsq8HXHEN2L1N4mMOVVV/hT78h424O7upGRSOHPmejQu3ycH8xIEw==
X-Received: by 2002:a05:6512:31d4:b0:553:2411:b4fc with SMTP id 2adb3069b0e04-55502c87301mr1341615e87.10.1750951940258;
        Thu, 26 Jun 2025 08:32:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf8rFHkE/BmB0i5oquVKLPGUsAhPwKnVvcvwGw0LvH4OA==
Received: by 2002:a19:ca1d:0:b0:553:25db:775e with SMTP id 2adb3069b0e04-55502c9e8cels259964e87.0.-pod-prod-00-eu;
 Thu, 26 Jun 2025 08:32:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhv9BMMMID15GpDgbMgTy1yuZ/yzHmNRDCAWwqsAZZ+QTZSNnM7odIM+osigJIv6zfHexDSR0wAQ4=@googlegroups.com
X-Received: by 2002:a05:6512:3c94:b0:554:e7ce:97f8 with SMTP id 2adb3069b0e04-55502c96fd7mr1487873e87.15.1750951937780;
        Thu, 26 Jun 2025 08:32:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750951937; cv=none;
        d=google.com; s=arc-20240605;
        b=H29WAob6QKyCqbXkwuEmUXcev1oMlR385n3CxuvxrsC8qn8lJy7Z9YRIKgH6kGZ9/9
         OBMJgv+5eHXp4EdnsnAOs0TtimSfoEEPJ5Ggt8v6Mxeuw+Ad5gwdQLzJSY0M+9Gbb3FG
         CW7cUs/J+nbxRcIgbpTP+qUiWmqsBSEvXu+TyLm4Ud/Lacr64s0dS7Wb3xqccs0Ss4Vt
         j2OJn3WCIESv6EASKZewDeR180DW9uZVKz2hWCrdLw3Y1O+EYn2fAutDoM/XaKxhTBQD
         Vn7amncv7qgF/bUirT3dAiiWfJMxLC/50bKuI0MC0L0FMVHFiGhZ+wGge41h3LXb+T7B
         a02Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=m8+Li4ZqAZW0QY7sIIldmBLFf6VQ+4AeP6Iv95ugt8g=;
        fh=1WpjcHXX+XIdfjHC6sWYRaaDRfNT2I6/aoCt7Sdsatk=;
        b=RTa06vkjd+PW1dvJtog4wXkB++os0K8ycvtmwTMrZ0jJP3WktNvnvbAvt5amEsE6YZ
         wIMc/2HIqUT/aKD/oD8VRi2OoHxZK8DTYaEk6vfTnX3NJXZT/CMZkgKKQaWZgDh6jcyf
         kzckZzhyVSgAHMoFIvlTUfYjJKOBlwmJZc7yOVZV1YXwcAuvI3Tce+lkcJymyF+MEyIL
         Z3BYCWXb4fjSXhWDGiudA2sDpDegkUgkV3NMb319yjJdR+A5/eM983yV2HHBd+0X+MZJ
         JzUsitsZY62zmck+nR8TcY0H541TDYF6TeP5XRlcvRgbIjkrQtI77uTH9Z0Vg8C90CZu
         JDEw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ejIto/+/";
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5550b24575asi6153e87.3.2025.06.26.08.32.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 08:32:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id 2adb3069b0e04-553d52cb80dso1357470e87.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 08:32:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUKSVRH3TqC/qbOHwxuWZhfx2XRN1Rc/gMfaa/doHyuRfxdfDXIMZ8SUWxJMU6hJfRmrZ0z9OXiZTI=@googlegroups.com
X-Gm-Gg: ASbGncsNhhlN8i9alpfgbDuRJ6pNY9rJ2MJa77OOTIoFuLN8KjK4LOfVgPmAGhDhpBg
	TkUHIj8oCGMjJXJuEMzdgvl9n2sEzbwcynVfuUf+KHClkdcDo/tLdEjf1rz6md8ZYPihYQ1xKCJ
	G5cVKZMJoSiVofpKKQdxmGi8TW6QC6zTzk5fKL7NLV+i6I0IASs2Gk301HXivhQiXUnoTZxpODG
	vGSd76nR0WdzUo0AnCoIaxD4chLzCU8fAo7V4UEYjh7iel72h+6pFPi8wEADcNGexi1qcXyeTz8
	E+R+srYE8N2gN33M6TvWmNruiuJeXrhQJmY5O3GhM/wGpLa9Qp5iQPD+9oSYQOA/IEK+QU7fNQG
	UVL4xT7wYS0rX2Tsl9RkJw5Ff2Wdl7A==
X-Received: by 2002:a05:6512:3e0f:b0:553:cab0:3800 with SMTP id 2adb3069b0e04-55502c95046mr1480652e87.14.1750951936982;
        Thu, 26 Jun 2025 08:32:16 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5550b2ce1fasm42792e87.174.2025.06.26.08.32.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 08:32:16 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	linux@armlinux.org.uk,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	alex@ghiti.fr,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	justinstitt@google.com
Cc: arnd@arndb.de,
	rppt@kernel.org,
	geert@linux-m68k.org,
	mcgrof@kernel.org,
	guoweikang.kernel@gmail.com,
	tiwei.btw@antgroup.com,
	kevin.brodsky@arm.com,
	benjamin.berg@intel.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	snovitoll@gmail.com
Subject: [PATCH v2 02/11] kasan/arm64: call kasan_init_generic in kasan_init
Date: Thu, 26 Jun 2025 20:31:38 +0500
Message-Id: <20250626153147.145312-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250626153147.145312-1-snovitoll@gmail.com>
References: <20250626153147.145312-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ejIto/+/";       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12d
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

Call kasan_init_generic() which enables the static flag to mark KASAN
initialized in CONFIG_KASAN_GENERIC mode, otherwise it's an inline stub,
and the flag is enabled in kasan_init_sw_tags() or kasan_init_hw_tags().

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/arm64/mm/kasan_init.c | 4 +---
 1 file changed, 1 insertion(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45dae..abeb81bf6eb 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -399,14 +399,12 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
-#if defined(CONFIG_KASAN_GENERIC)
+	kasan_init_generic();
 	/*
 	 * Generic KASAN is now fully initialized.
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
-	pr_info("KernelAddressSanitizer initialized (generic)\n");
-#endif
 }
 
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626153147.145312-3-snovitoll%40gmail.com.
