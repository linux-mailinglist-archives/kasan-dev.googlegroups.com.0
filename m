Return-Path: <kasan-dev+bncBDRZHGH43YJRBS63W6TAMGQE5MGLAGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 77101770E20
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Aug 2023 08:35:57 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-6b9c03dd4f6sf4719256a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 23:35:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691217356; cv=pass;
        d=google.com; s=arc-20160816;
        b=X52oi+Wi4XP2Z8wLZecUcY/Ht/QI0O+0XxKVRPtkscva+NZ5+izWkzb4BkCg7nfrJ4
         NWEM246rxS7u5Hogi+j+FCdKduVR14Qrb4SCXSCtZtkRNsYZxT/00DDhg18Q80LWPmet
         fGKl6Xn28oAC///uUqQ++WPdJNg6EThhCzKIQ+ZRUMLzQ/qtLo+9IaHNwqIclOhAOQOl
         RKSRL9vjKBDvrj1q9E+2/nW1Hf4ExOvRP/7zi3kTnoPYJyyxQDfaIOtchk65F19SEMft
         T3lV0E3W9q7SDmQNI8c8sn/p7h/vSnoQvXsdlNNn1+lf94MheyI+2YuYNPV58fs1hzq/
         GKww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qXrFQK2NBhI5WABLIQnq0syVUhcEd/g6ozlrkogu264=;
        fh=ddBG0PQlFbsXocASPzii1IUg+ZNxr1a5intutk/ig+E=;
        b=a1Www5QLErXZFpSD2vfaU3cS6w5MvaKdduY/z4jxNwXN6x+RhDBLR14JzOw61BoQou
         GCiQJNmFrZOGYBDwKQXIEzdwFrkxc6h8PGoK6NITqOusN0m+O78Mo0UhOIn9fwnuQq9Y
         zlSe2TDGd75EGPVtmyFPVMOyiETRDshVXEYBgGGFvA78XQxPeJGpIfMhCDTRXCwEAGkn
         0IzJ4Mso64YXHjqxrFChRromMHpIF9G6mQDp1J6fo7qiub7cajf7SNoyS6INMfWeemE3
         o6Tjv9m9WgtDlwtrHCh4PlUHxDQi2AaofW6cWYImhNHbBi3I+nt2ZEw/4aA1DeVQGNdV
         UKNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=A707mbbr;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691217356; x=1691822156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qXrFQK2NBhI5WABLIQnq0syVUhcEd/g6ozlrkogu264=;
        b=pIenpXLpQe92PfDtOkJLCyfIuzna+X5SyIJhCWjIJOyw2vsuIy2RPFUIRkzMoxaWv9
         S5fBBcaNrUwYF6KhzStMSRUdOiVVKbA61JW6q3kLzTeG1JnG3XCJRF1UsHQTuiHc1+zy
         C4PEuPT3yCPvBqF3u44pUICnnSPF67j5G8beR9l08R2xH4FnbA83uOCRCxcSknbphTCX
         K3IGYKtCIpasHHZh6nLrv6GEnWmfZRA4uJVEJY9ZRl3lFk+AIW6EQTB4ljL/RuQOGX1x
         DczQx9CeuKNRu+DzZ57rA4Sox4yPIsJ7Gy3gjAV9AQKfBLs5i0f8PeAfY+Pov0SMDnDH
         PcXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1691217356; x=1691822156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qXrFQK2NBhI5WABLIQnq0syVUhcEd/g6ozlrkogu264=;
        b=lBS/siNG1Fv4bnw6sawOsJ7XUBalIMVKcVxYVOJwHMSbUIVpKORS03uCHij6covDSX
         CyYdzmcfh8R4QW5dswJvmRAmxqsn4y5hiEZiZ9KXj+xeoe7s2f5xG9zEONOeOU6ahUyF
         KrKXFHVwR1rFl/bLSqkx/JzVcGMfoFsaeCyfO+Riu8m/YgpnwDwZ5bcvWIVWAaTw6GrD
         h0Bxb7Zglv8esIQtZGCPn9fv3JND9sbnXOPMNl3PxXzcl5ChnVcX0Jh2GYEcjhVi/rv7
         h3/6Dgjlm8be2KL43ezd/sCzxj5eN+j0Xao6VGJbKqnUGHelDu9I6kAnF/sEZ4h8a9ky
         KQ5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691217356; x=1691822156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qXrFQK2NBhI5WABLIQnq0syVUhcEd/g6ozlrkogu264=;
        b=eSvKRqv5qE2GO0vDsjIbjBw/CEw9zc0+44jWbAYw6E7sfs0FjmTziTw1ccYqb6E0u4
         fXy+PVj39BPDAyQyb4xSEn3fNodMSan3ipT2XeufSjy1MyIjBa19FHjl9WsG1elzygzn
         oBTmFU3Kfa6PdDRXlDihXLZKHoowh6QnJO1XX337isBHKdawkg4mbOwh/oTiBJRk6JN4
         sGRnDujPT4W5PXmIpjQ1ZwBLDkbBS56XZDnWSsV1vXTNLMjM9QFUNn+uP0WcQfWRf15O
         0kDGl487XxTVcDhx9eksSbtGwYUHXM4hiXwjMNv2ZM7PWJuHS3aT98yRAzlrrkVqNdRZ
         ITwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyyHKPOoJ+tcVH06XqLAY/ExdNRzlnA5YTt/TsvOAIb2EvFriKS
	6bLmukfUOlqg5SiOYTazT5M=
X-Google-Smtp-Source: AGHT+IFv2SJyGTM9QRAmm97K7NVDz/MoBfU42WuMKxQv1byEdFuY3hTVq1i60qwugiZ9abPbpGdLHw==
X-Received: by 2002:a05:6870:f6a7:b0:1be:fcb8:6a48 with SMTP id el39-20020a056870f6a700b001befcb86a48mr4710930oab.58.1691217355468;
        Fri, 04 Aug 2023 23:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5703:b0:1bb:933b:e6a7 with SMTP id
 k3-20020a056870570300b001bb933be6a7ls1120732oap.0.-pod-prod-04-us; Fri, 04
 Aug 2023 23:35:54 -0700 (PDT)
X-Received: by 2002:a05:6870:428d:b0:1bb:8483:a807 with SMTP id y13-20020a056870428d00b001bb8483a807mr5075207oah.44.1691217354781;
        Fri, 04 Aug 2023 23:35:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691217354; cv=none;
        d=google.com; s=arc-20160816;
        b=IkPkxpHgdphEkUfMX5CZ8643tJxXP2pdh0WbvClYoSfoW2ItsNipG0NINNmdMP29iC
         c+KX2v47NzNTSmb1laJCNpKA8GTKZDpemvziI+UiYwhiZ4ziBvPhzmEVdQf++lUiFgyC
         /47OQ9Q+ozXoRVgF7IlAX/kQdMbUPG4OWMYJpyd/XlOPD6UVIM5elVxXU2HRtiH4hsnj
         FiXJb6ftQmObZ6F3cj6WP4tF9DoCF7MPyebQxNpe5YL2N9gWlvD0nNYqFw+Lyn56qQ34
         GTNLnNJ4u8t2iYcD+bswj7eToLhMaEUOvzI+XfLlJQ+NZ95ESUx07dwsmsS7zB2tvWym
         5qag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=izJldXkK49lbGL0XLPukfeIEvUvsLq+UDkHmXV6tSds=;
        fh=ddBG0PQlFbsXocASPzii1IUg+ZNxr1a5intutk/ig+E=;
        b=r18nvGZO2ftOZghEi1g4XUB/2QMmfnKhyFCy2peVkkljqt9at+NJJKb+HIveHSaonm
         N6v00PbxO8UkU9DpjU/vRtSEYkXSBklzud7/al52Zx+vu5T2iQyXIOFvkGdkhnmJsq3h
         pro/NN8AXbqSQgdRPM9H+UPWX/0CTV4vSLrPn6MWAepzK4JE077hGnQ+FUUnqQWCfubo
         5H7X8c/weFgckJeuXkJyOt8KcifPHE1rqfdChqXH/eWnOJBJStJkh8hcM6i8FksJGLvN
         yMXqii9sIw5Et+wh0K185OvPDJTKRDzz52ltKktMPV+lebn5VwjR3BqEMUD1sOwJXxV8
         SOOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=A707mbbr;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id w12-20020a4ae9ec000000b0056d0d3dd2fcsi259965ooc.2.2023.08.04.23.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 23:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-583d63ca1e9so32530657b3.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 23:35:54 -0700 (PDT)
X-Received: by 2002:a81:73c1:0:b0:584:3140:fcae with SMTP id
 o184-20020a8173c1000000b005843140fcaemr4139723ywc.26.1691217354314; Fri, 04
 Aug 2023 23:35:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230804090621.400-1-elver@google.com>
In-Reply-To: <20230804090621.400-1-elver@google.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sat, 5 Aug 2023 08:35:43 +0200
Message-ID: <CANiq72=-o49qkW+mPW45P_+jbS2jO=5_qks14HOtzVOukb0Mpw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, linux-arm-kernel@lists.infradead.org, 
	kvmarm@lists.linux.dev, linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=A707mbbr;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Aug 4, 2023 at 11:06=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
>
> will imply notrace. It is recommended to restrict use of the attribute
> to functions that should or already disable tracing.

Should the last sentence here be added into the code comment?

Apart from that this looks fine from a `compiler_attributes.h`
perspective (even if we are not there anymore):

Reviewed-by: Miguel Ojeda <ojeda@kernel.org>

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72%3D-o49qkW%2BmPW45P_%2BjbS2jO%3D5_qks14HOtzVOukb0Mpw%40mai=
l.gmail.com.
