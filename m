Return-Path: <kasan-dev+bncBD4NDKWHQYDRBL7E5LDQMGQE422SWPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 739F6C03B96
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 00:54:41 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-87c1cc5a75dsf53972606d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:54:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761260080; cv=pass;
        d=google.com; s=arc-20240605;
        b=efbYEoIShwuLPRdyeptkUE8UkLa4hzCn5qL1+rc45LkGcUR95To8m8HEJTK+oMOd7Y
         BD5HsGPPcpoawA0VNwpWDDsm3F5DbmDYkzLOXyK+ImcbIW1yIQ/Vv98eiGmOQUeNY2Ko
         3npd/a0+ari0DaGC35v9QApRMlo+x68CVitnD3pZz2lA0ez2xNx2C+8yyCGPvhWnbG6T
         Xa4wE9kiC4wxC7pixaN8k8kxTzD6eQfH1Jp3nKGy/RZp8gsRTdk+THtjUKNG37u6E7gc
         VcQZoBi4gEGyTPRgd1tWmXo+0798gS6xZ2nUovvwWiuh6G/fjBIkyyE4ZhMTjmFVHGbc
         dcBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:date
         :message-id:subject:references:in-reply-to:cc:to:from:dkim-signature;
        bh=uhupbVbbym91XY9vnd4gt7gsNzGaQ/Tbzdg0y7zo7j8=;
        fh=rMmDU5H5mhLuutY+VfRYBBp3Fa2t+RdKpfgs5mq1fuk=;
        b=c+LbTywlq8enbmjqlBeOLIq7lpH9nstmT/M/DPwaQDGw7mJdZfm8JQdzZPXLOJdUlk
         ke6lXWy02Paaz00uNkZbfhJp/1hLrpAw1OyGcFhwI6MaaCq6XjGlk2a7sGnxCyOtoDGb
         nNVgD1iPJmKjkzdgBC43pZ87HTEjV6djm1AGBZWeDPkSPLOkGBGS7DY1PAugAcjwesGE
         yMgMKvsO1rOf7DbPyGk3M3WmCkd00Qn7JExXMk4kBgnpJRVcV8SKdHnIxJAkYlueCY03
         UUGEN2uE+CMdNUAijcuX6ell8PKM4DF+XFUSwL5H/KskpmJp/wy2b/YfDAthzceGWdt0
         VjDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OzRz0FBH;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761260080; x=1761864880; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uhupbVbbym91XY9vnd4gt7gsNzGaQ/Tbzdg0y7zo7j8=;
        b=J0RKFFlmKpZ/mV2FqPOerSsbkVC66LFLVxek7QAefduU7IZr7Xg5+69WNuTD6Yqa7W
         CaMACLAaJyeCqnmlfwPF2eWWwzRyzhxmfkIEEIg47LdBTPRoirFfgWiZfI01IsZaON+k
         L730n+b8BUQFgXxLbYTkfn+L5zSipYJjBoV6vp80esDYiMcUqrC/cth+jZsFtBV/+0ar
         ANFOsR1/eakfeFY9sAHBcULGysuyL3OWwlYYa2JCCVALY5yH4Uvl7iFq0Jd2ub6s0N2F
         FXqUaXum3qWBY3nAVYUp4OIDZPGVKcQXuq4QfZ7VxGwKK8YZXCKTriEFjgi+Nd7oPtXm
         slEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761260080; x=1761864880;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uhupbVbbym91XY9vnd4gt7gsNzGaQ/Tbzdg0y7zo7j8=;
        b=uF74VkUWiIHHDSg3Deay2OAz+PHlKg8BMyuOSThG1uSkhXzxTtWU8WOg8rqfbMh08D
         o0LH0aWY8L8k3iIAvGnDE98lOjWtNpxagJbx8bkKIvr2xHUts6hcadrs20YKnTcdjE7h
         KpmzKhfbpQz/IbwaMEN2l/1iwlIFu/nKfIP9OaUAMRVtqmntIsODfOqFOPkZepWVUnff
         IjORbei/ieIVcwgc3yBqPdewjpel0N6Z7nCCKNwAlgqOKnO9un4qWpEd2gxLPRiAMcNI
         8z4bQaXrDAbANrWnW9TRDh0Ozvp/7BI9ZldKzY5LVKyejU08iq4deMTgkzSUEU+uvDnh
         6Inw==
X-Forwarded-Encrypted: i=2; AJvYcCUiuWvV6mTQ12kFuEfq0g/ECl3I2Q3/mIBbvI1WcuF1RMxyl1/RQ8HbCQFr0ZtIy7ZtoYhyxA==@lfdr.de
X-Gm-Message-State: AOJu0YwImm5YMx9+Kvv3QPI4TUpLj/j66fuuwUTkj/DtdlLQRRR0kRPW
	e6lwTq4xpqDiHUJz41TeHZdd1szjUvUadt6EeJCw6oGUs7FW/1lLUkhN
X-Google-Smtp-Source: AGHT+IHF94XxKCqGWzfTmU9PwQ3JhYU5bEgtWdHmrMBXiAnTjN3jAb7L7FCCY3hNnXImGVLajwcXBA==
X-Received: by 2002:ad4:5c6b:0:b0:76f:6972:bb89 with SMTP id 6a1803df08f44-87c2055e48bmr331819856d6.9.1761260079776;
        Thu, 23 Oct 2025 15:54:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZR0Rb6kjJHSu5S1AXWOkMmKt1kwwZcQN1JT3Xg7W6SEQ=="
Received: by 2002:a05:6214:f2b:b0:87d:f599:95a8 with SMTP id
 6a1803df08f44-87f9f9b33ffls26010256d6.2.-pod-prod-04-us; Thu, 23 Oct 2025
 15:54:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWfRBfPi6+zPpfXwZUEp6bsPgCEMOxaEFvg5zZayn/TpvKGGQjmm40jZLQngJ4QAPdFyxz/OMzxI3Y=@googlegroups.com
X-Received: by 2002:a05:6214:19c3:b0:87c:3b2b:c12 with SMTP id 6a1803df08f44-87c3b2b100bmr239277656d6.60.1761260078832;
        Thu, 23 Oct 2025 15:54:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761260078; cv=none;
        d=google.com; s=arc-20240605;
        b=iKkwoqpVrni5e2HOX2Mjw2M7w+aIM6siW4j1x3Kw837ct5OncrmlBKl7Ya/ZpePDx8
         Ab4Deok+xMprubULvyxYMrTUX21GpYyl530BMt6cquH6OV0TZq24f5WlUGiD3/rEnf7j
         FqMU2GUxeh+UtR5eqjiK4hpG4Aa/QNTKZoAEhE0CTrDByCqZ4AcwX1ig72tJ6I2G2dsJ
         t2Z9bLWKBChLrWC1LdORATxdXhWwiDOUm7YisfOyduedoqEUQt/Fp8nurhQZpOG9zi+o
         Q+jg2FZ2Za6tq/s/WwiFHiuqkRDYwxyu6QSSsqm6xlHihgaLyE9EVEb02skBAo1G6pzU
         EOBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=gM356DhkbO8rZroS+AffT1N8yZFJvZYuyikVsq71PtA=;
        fh=LW01DrSCQ33lCCt9v/G8TRRCFdNU/DFx9D9sqOk2qKQ=;
        b=asrxUa3mUDMud3FQ/GF9k3tgvWvVdVRE15b1BMg6S1240XQj8g87ngNGzOz4YpI+jT
         nPSzgbLiLu47Eu/7qHA23n89zWwibsjMxg0AicGCl21O2jDwT5vf2ABEzi73OSKDDIc6
         REuu+B/vXixoLmyFWaXTAceZBOafcv0k0zTIq7akC70B3jCRopYwXY9DWhqXUqU9HXoz
         PD9goLV1uz8XY3e8/lB4goJqLukfH83nqkhkREGR2gdtoqAnqIx1I0oSi33WBR4VeP0d
         WUDABhC3zczQ7fi/9eFqMdYYCH9yoVOOsiAJruQ3nFJkWQRf0tpmG3r+E4OSE83aj19K
         9v4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OzRz0FBH;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87f9e731195si2573506d6.4.2025.10.23.15.54.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 15:54:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DC2FD43960;
	Thu, 23 Oct 2025 22:54:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4A12C4CEE7;
	Thu, 23 Oct 2025 22:54:35 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nsc@kernel.org>, Kees Cook <kees@kernel.org>, 
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
 llvm@lists.linux.dev, kernel test robot <lkp@intel.com>
In-Reply-To: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
References: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
Subject: Re: [PATCH] KMSAN: Restore dynamic check for
 '-fsanitize=kernel-memory'
Message-Id: <176126007537.2563454.16050415911756189258.b4-ty@kernel.org>
Date: Thu, 23 Oct 2025 23:54:35 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.15-dev
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OzRz0FBH;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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


On Thu, 23 Oct 2025 21:01:29 +0200, Nathan Chancellor wrote:
> Commit 5ff8c11775c7 ("KMSAN: Remove tautological checks") changed
> CONFIG_HAVE_KMSAN_COMPILER from a dynamic check for
> '-fsanitize=kernel-memory' to just being true for CONFIG_CC_IS_CLANG.
> This missed the fact that not all architectures supported
> '-fsanitize=kernel-memory' at the same time. For example, SystemZ / s390
> gained support for KMSAN in clang-18 [1], so builds with clang-15
> through clang-17 can select KMSAN but they error with:
> 
> [...]

Applied, thanks!

[1/1] KMSAN: Restore dynamic check for '-fsanitize=kernel-memory'
      https://git.kernel.org/kbuild/c/a16758f0142ab

Best regards,
-- 
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/176126007537.2563454.16050415911756189258.b4-ty%40kernel.org.
