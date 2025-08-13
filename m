Return-Path: <kasan-dev+bncBDW2JDUY5AORBQPY57CAMGQE5M66DIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 79FBCB23E55
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 04:45:23 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-55b861d06d4sf283757e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 19:45:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755053123; cv=pass;
        d=google.com; s=arc-20240605;
        b=YrTAkGSQgDIVsfZZfSpuxtntJe5wTkpGVOPFUzrjcDR8c3a+9wDyDNAgIhARQVHQmR
         AA7+wX6SUb7CGJf+egQ/SBqbWwm1vCKEl3w0YZFATUO7PxCrjrm2TyYo6rUcJvmAbdXB
         1asbEkZmyiSHV89tWzk0OWsA5W8YkXvWN4zxS8iz3wqxqlt9t1lcrMOxMapgP4bnTrE3
         Z7Sq3FsTukguKHCRpQWJKftjSXDjPxRZPm8z1UcGsPvjUezr3Nm7W6Isb+FztbPtXbrK
         U7G743yRnWJXjQFAVn3gfCU3NFhhWGP/6LnvKosm6lnS8Y0Q0JiE647n88oGuHzPQXPH
         Ljdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/cJmRkK2ZYw1A3iVoIb0B33eATixCRwEMNFJhyoHjfg=;
        fh=GndBvhtl0rfJhB03L2PYiZsEijRWcSEEUoNCq1cgexI=;
        b=fDetW0r38oSznDNTY13ws/PJQJsRtArPJBJ8GUdKa3R26T6HfGOF5mUdfy4vCXaRb8
         hrirIhexrrdOH/1SAGK+ceE9jaStxIkkPf3/6bKTWIqxV74EN1ERtO0gGt6abNEhlNpn
         adqqnkLHfsvqu3RjkCyxOnGiJvaSHNVLqzuwXohxbK9R1D3m64w53qfICkjGY2G2sa8o
         xZybSqFuzhuvVEYm9MMt3q+gGN+swuNzEGM4Yp5Se8NCdcrXVdqwkHK6xwqOoq59ap8O
         /q2GYoSorq/Z8Jv/4epdC/PPmz4GuzITQA1yGPF+eB+7ABo8cjk6wtzuuShNyNpuA39Q
         O15g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R2G3VMjj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755053123; x=1755657923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/cJmRkK2ZYw1A3iVoIb0B33eATixCRwEMNFJhyoHjfg=;
        b=fTxlok+Jx5HPez5u0SHTQE7+30JU1DEIh2KMgUlzUIUkZ03CoA0BGc6FLR49ieeLTj
         Eto77toioypZLsC/nrFXpXOoWIZxlEyk6YOgg7GU2PmC+NHelEHxpXoRnlGTa/dMQsuk
         pr3mZ6t6oE7vpVInl0TLMXU2g1aBsPZks1qWUgaDuqjN4A98cDkC9c2HUdG/JplPKcnS
         YH6UpiE4eo1ZLjE1IlcfRLMYQTsFilPAx/L8rr/PRcT0njYB5FHFysvZAFGbqvdLy0D1
         KviWyyTcfWpduCNxgtz7UNBfdrMtWSMNpsqNCAUosEtp2LNoSFK3WmbDvemYvL6kcGqv
         n00A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755053123; x=1755657923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/cJmRkK2ZYw1A3iVoIb0B33eATixCRwEMNFJhyoHjfg=;
        b=VB2Or60CziS3d9QkoHID04NCQmwqleFRlyOwTvYe8FzdP9TDUIHNay3U/hsVZDJPvZ
         cmCxeQeoKqUoxhDlP9OxW3k0EtS45LiJdc2iFi4JFwKsXRbOAjTrA5J75+QJtgRip7ON
         H3JDyYwwEtz3upTvQI7SWa0cWPUcYVI0Yjz6CdkNvS/WaCRECX28jP0hQ6K9Hb6sV49q
         8rDRWjV4jggdqabE4Nf+U1Z/gPKq/DM+EgqfzGXiHxZ8dtTb5qEdLw7rBxIMlOJQYVi5
         T1+YiCEctV4fbk7tIvA5qoWMAcf7oU+SOm7azTq6PMIhrujGjUB1Sx4zv1/Yq/zx3GpX
         moVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755053123; x=1755657923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/cJmRkK2ZYw1A3iVoIb0B33eATixCRwEMNFJhyoHjfg=;
        b=vyWLbua3z07EAEsr/52TlmTjVaFLu2di/RIkvhRwf1qotz4jqO7NB0dxI1dAIPjF2x
         01MkjaPzpebQtdAzYQkxlj9fU0RrZDg2w1wH7TQMd4yCYHlRaiUZ01QE1jetjEjgE72N
         TJHzVdBfzAs1t1CWxR23f+5XnyWlVHJScI0/d2IXtggrMSpJPeFAmFiQ8UVE6+0CJpcm
         R7KKfn6iJwAshZx5qBhPqLdcjJZ/aKA9JtG/ZP4YYUgbvIW23LSCT/mZ5r85r04Wse2y
         UrRAFeMYMSxdi2v+8eIQj2lkkyD5QOQ8P45OohQYnjFthuY31bOw0DiLMlqtLXIR/l4Q
         J5Dw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8mn7b/yp4XTu55Y2nBGAMlPo0L9X+mVLW7MDhIWOkZ3lbHNtL+PrY2pQIIfuaptW/UaQnXA==@lfdr.de
X-Gm-Message-State: AOJu0YxjpxBK97dgeRk/AogEIrBWS8SXDmAtvFbB/8CCwPW6hS/F8KLv
	N/RgdTj9OENc8NubO/kXR4EsFHt+qgKthgWkt/lNWKVTYZzBcYOdXAE4
X-Google-Smtp-Source: AGHT+IG1GDbiT5JUErf1o/GeqXwhw3QOfBSDxcV/7cAnJpltqv64PKgcInb4bStyAmc3Tp23MtAP3g==
X-Received: by 2002:a05:6512:230d:b0:55b:8038:ffb4 with SMTP id 2adb3069b0e04-55ce13f7b8dmr228216e87.6.1755053121904;
        Tue, 12 Aug 2025 19:45:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc8xURPvPw/DeYmxkm30kuP2h/H1/CO4ngQtzjPOITkKQ==
Received: by 2002:a05:6512:22c8:b0:55a:4f5c:f12e with SMTP id
 2adb3069b0e04-55cdfd8c78cls40498e87.0.-pod-prod-00-eu; Tue, 12 Aug 2025
 19:45:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtnoTY76E2LYuzgsUojkP2DllOfZ52FUYo3bj3MHo6TS0bQKl9b2gXDTcEKrKDqMfJfLmQYHZkTcU=@googlegroups.com
X-Received: by 2002:a05:6512:e83:b0:554:f82f:181a with SMTP id 2adb3069b0e04-55ce13f7d19mr238679e87.2.1755053118694;
        Tue, 12 Aug 2025 19:45:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755053118; cv=none;
        d=google.com; s=arc-20240605;
        b=LOgVKA/0PAnv7vEsrf21MAUGl6D+XV2iAJsQXs6zAjJ7QR7fbjl4smV0JkYIy0btmi
         u7gv4qddzHvroHeopqLCiPmqTB9voGI2mfTER4p7Lylmi48uY6+0gLomf6VAbIXMvhwM
         nxFq/d5/DSIrRAOuponHvMq4mi6jzUWrjS4pCHL87ocZRLhEnAV/WVe+c1ylFaaQKRDq
         O/jK4MkNYvA7Psctt007EESFItRF7x8Xb69gQx+wG2v6eLOoezyWTnDrJzSyi7iWXqbm
         aKW4ZrJIHNjwbw0VYwOkRRfMiBnF+KTXMnrThXZRNRyfg0jKlbUcA/evdskst3uAwg7n
         FQlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Kvg8fvdZercb/1tUH1fx/ZCsiW65Avvhaf/buqFYuWo=;
        fh=HM+MDwDmqyQh8K+QEpQknQiaolIkFPI2WjZfSr/lcGs=;
        b=M63ZKAz8z4ao2apyf3hf2S6dgTMVnm+zAv1+phg8xyBvQyl6nLOnmWW4UJ7jXIwdMI
         yEK0sbPfpI4Hh+GtParm2qRz2OCn/yDiuH/Flvw7T6B4Ymw+2BukWoXcCH0hZcRw1duH
         kg21DRW5M5SjR1iNlhIwd5n2+keoehqK1+1XcMmmbk7ns+9dcJGTmaG2z7N0omwXM/HH
         658NGICyOpKkI0pAKX4ZQoTFdpG5gwInGpCnphQ1hvtjCOjgE0bgNsBnCn1XnFOPN0YV
         Zx4YazPbmlzCGbTvEwUIRmYQVhSaY3SDr7+4uuvGF7NAiYQYPeFqXQDb7hblfgIRcT9v
         D2lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=R2G3VMjj;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b9a222e4asi680395e87.5.2025.08.12.19.45.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 19:45:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-458ba079338so2428415e9.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 19:45:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwO0T0X0R7EUsy2BI9TmXV096gU6rXMS2m0KlB4/8QmlOcpJe+R/MvisibPqE+lQb7zflBrrMjvNo=@googlegroups.com
X-Gm-Gg: ASbGncuUegloxHdRJHFtRognMZYPxFIto1+Dibon8ygWpsQ/n593N5sM1tu3LqN6H0V
	4TICaPJQE4BlfWs3KPqTD38a5LSNspyRAeL/faMfYA7W3GqruX6wO4KvK7R29ViDUQlxHPnj2C0
	i6ebWcUSRfA3mfnw04EJYrjkXZP57bp3NP4x2r2K5E5dzY30X/sxbDr0OWSIHwUeeHtROHQheWb
	NipWZI=
X-Received: by 2002:a05:600c:4e8d:b0:459:443e:b18a with SMTP id
 5b1f17b1804b1-45a1704f681mr4589345e9.14.1755053117827; Tue, 12 Aug 2025
 19:45:17 -0700 (PDT)
MIME-Version: 1.0
References: <20250811173626.1878783-1-yeoreum.yun@arm.com> <20250811173626.1878783-3-yeoreum.yun@arm.com>
 <CA+fCnZeSV4fDBQr-WPFA66OYxN8zOQ2g1RQMDW3Ok8FaE7=NXQ@mail.gmail.com>
 <aJtyR3hCW5fG+niV@e129823.arm.com> <CA+fCnZeznLqoLsUOgB1a1TNpR9PxjZKrrVBhotpMh0KVwvzj_Q@mail.gmail.com>
 <aJuxuKBm9qfpVkBC@e129823.arm.com>
In-Reply-To: <aJuxuKBm9qfpVkBC@e129823.arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Aug 2025 04:45:06 +0200
X-Gm-Features: Ac12FXx6Pc1KJl2LaFe2eqFw1_0jb589tm6uNaUFSn8Yw7SbSnihGg_Kc_aD0sw
Message-ID: <CA+fCnZdWOh3=KkM4AL1ZYfhyMhdSqgW97Rz+uxO88mMkqT6WTg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: apply store-only mode in kasan kunit testcases
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=R2G3VMjj;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 12, 2025 at 11:28=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> =
wrote:
>
> > > But in case of sync, when the MTE fault happens, it doesn't
> > > write to memory so, I think it's fine.
> >
> > Does it not? I thought MTE gets disabled and we return from the fault
> > handler and let the write instruction execute. But my memory on this
> > is foggy. And I don't have a setup right now to test.
>
> Right. when fault is hit the MTE gets disabled.
> But in kasan_test_c.c -- See the KUNIT_EXPECT_KASAN_FAIL,
> It re-enables for next test by calling kasan_enable_hw_tags().

But before that, does the faulting instruction get executed? After MTE
gets disabled in the fault handler.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdWOh3%3DKkM4AL1ZYfhyMhdSqgW97Rz%2BuxO88mMkqT6WTg%40mail.gmail.com.
