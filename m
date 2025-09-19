Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUHCWXDAMGQEICUHXDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D4E3B8A2B6
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:05:54 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-6219458790dsf1778502eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:05:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294353; cv=pass;
        d=google.com; s=arc-20240605;
        b=RDpufO7qO6C729SuWpdM84bWLZF5CSXkaEZXgMAUKT7lJDCw2UwWPw8tRTseT/UZwn
         PZZ0LZzZ0Yj2MWTCp9mrkU7Ia9Nwtq9rWRh0GhK2/jCibXwxgfbsLCVLtwkTp0mG4jWc
         c9lW58BWDcbaURxcQFHTzoktPdkPot1BX3ABwinQopTK7NS9jXTqWf4+QX/e52RdcK61
         o7GqoAN5KfP2zFHnfmGDQgzXA956mxRHYl35+1Q4AD1u0lIUiu8NIO5J9Mn/bGgWgkEt
         J7oGNXy2W8vrgaIuB77VMABxN+OcEkidYkfX2cE2oBWg7uhAeCOeSmLjPVHSf8n+m9Xm
         M6JA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H8/zJGmsdBiLSDxZbaWZRW290/DheajJaP2jM66nqXc=;
        fh=ucGJ07X6yYhHk3UggDQUi/a4qiNScOM+uEMJia0l2KA=;
        b=Pf9Woy4k4G18mMjZi8j16HKSH/Kd6wsruYUqeiVXzlFWtZVhri9TmZzpuaF6gdeWdc
         QeUt8TpIP3xa8RicDsxSuIurkWMpQFI3ZLDSJm0eJaqCQnvPoZE/7cxihzeR9q9bsd4g
         ZbgjrfgcuCUWrSx3J2O0oC4+KJAyLEv2+yQ+OVJ924WiCg/IxpMXFZrWSXupTjNgwc7U
         UFGpA8zpnkXEikAERkzmNn5zCO77nm6PwEuK8eGt2Qg8+/4+enoCoIpgIyxlFx0xCnD6
         Gfj31izzyQzu1CMNG4f+B34/zavJ+lWgJcEVlGLUSVVFRbO37M6hbXaH2hWHOmL2tG0s
         hSbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XhoWvj+H;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294353; x=1758899153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H8/zJGmsdBiLSDxZbaWZRW290/DheajJaP2jM66nqXc=;
        b=f89f1B623NghqOkGwEw7pfBImd31V/2SPjJEtZyw2aEAnJRzMStbCzX333rvQiZvt2
         qCcDgVROOnmIHusL2WPQ0XNAR8iujBha2tDalcX/iBdZ+gUJH8W3Oy+BXbwEVMRP8F0D
         o1apc0YijjDMIamjUxcHytwTLfbHGUgK5wLIj38ybevp+VUo+/h1ehcCw6AUM/YhhCZj
         R+YAz3WH2eEWlaqKJPae27gHm5/KPg3hNcV0dWYeO0BL3/UCKQNOYfRMnqc3gJxUDqFV
         YPPp/3rSI35VXhGTsuDV3gJQgxhvpNZDF1tXhPjJYPQPeKE3+0mL+5fjynP93u8aYSd+
         7dbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294353; x=1758899153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H8/zJGmsdBiLSDxZbaWZRW290/DheajJaP2jM66nqXc=;
        b=HtoEMDHyByJm6TAyhEdi0zwmqbZJitBgX6VZuxI9x2xTMTXJGkee5PgWg62WBYoHLe
         CL09wxqiYEaaE1aPQIMS8mo83qPNXdi41xLGBKbG+4ickjkQicM1OEzrWEDN2rlmAXPk
         0EwZGah36WCIOLvNvunwrg6lUt7GoA+Uk81SDlGdA3CFuAIFJdKsvJgVOMNP5b+UcZde
         gAQdBSZzxLZ4JAHwYTuK1qJPPCB7lAk01Vxf7nVrO4DqOKJnQaHaQZoCGjz2x0JKP1p4
         XBeQMKqQS6CQr80WGLJ5FYSMqZW8kEikfJXSvwtzX5PQCmg/qI4WVyVej4BkQWH00jlM
         OA/A==
X-Forwarded-Encrypted: i=2; AJvYcCW7FrJHJ4bQzQ2sgkn7wAnl3cK7xxa7ent0g8OuGmEVackz9p7CoXKDqTMyVYt/jdMKwHvXXw==@lfdr.de
X-Gm-Message-State: AOJu0YygQjpMognLXt41bM3xctP8BqqWDQxtWMg1IQZM8GSZABj0JBxG
	eoHISF17btIfB66K2TCqPMyh19yHMo9Kqj0GfUZeR+qEUfTe4N7wShZm
X-Google-Smtp-Source: AGHT+IFhcFi4du0vf+5rKuLTT6bRB7uh+3hE8N1ClkR39QAfBgu28nZ01BPuCbeZmYuNlahGgK2kCw==
X-Received: by 2002:a05:6820:1b91:b0:623:4571:36ef with SMTP id 006d021491bc7-6270ed73226mr2173590eaf.1.1758294352574;
        Fri, 19 Sep 2025 08:05:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4myIFBonV0x25zobS+//RKy+jYEZefT/+k6Sg4dsjS5Q==
Received: by 2002:a05:6820:7617:b0:61d:f8d4:b31a with SMTP id
 006d021491bc7-625e11532cals350830eaf.2.-pod-prod-00-us; Fri, 19 Sep 2025
 08:05:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWWE/dkwYeolcNg275b5cMcjYIGqAErGF531SXg2f8K+1HwrMg5ofq+0nOmDOCBFzTzuFHxKI84u4=@googlegroups.com
X-Received: by 2002:a05:6830:6103:b0:747:f92b:235b with SMTP id 46e09a7af769-76f79eda76dmr2519610a34.14.1758294351177;
        Fri, 19 Sep 2025 08:05:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294351; cv=none;
        d=google.com; s=arc-20240605;
        b=C0T2yE6iLr81w7DoeqzKB0l0tJ13aY6sNZCBiNRRTwUtOC9GGhPdSHRCgbh5oBFNnr
         zbw/7bH8w0tW5vEYUbnp1huF0COlDrdij0kIqfsA3aGsMLr+g/kW4gA/MtjXldhvfuHN
         yy3Ti98WFa3f+cpQYCcc1/TL7vUHeVAb7rtmsWONPB7RaeldQpn0XvPyfaMNxTWDCUAZ
         z+2Bib3wFYRS/QYgWSKd6CnSVUi7pGPkv1VzSlagPaRdY574z1g4Wwy2sauCDwR/jIQw
         VvJtSnkhjDzRkkO0bTsHFGwoXp98RgxnRIe2q5eJm4xGxAomvbjoaiRCqmOVMy5gFpQd
         h7Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ALVFhndHULwyH6PXNjxWdCUnJjL9si5BK+FmNKNwS8Y=;
        fh=J3kucPcpgQEbbRBRrJyPItROwptrmQH44p2EEu/O/Pc=;
        b=ZldNNJdddKXX+BiRmzpTf6L7uiWcnhf+MzVGhfMy/ApCVZUNMUwlCRGwK9zVMnijEe
         RVnmb34mk2Ao326s7bRp6y3S0TqRxeEzabtk7Dumgtic/8KEAMYaxqjI+dkywsYfbzyE
         JQiYHB23nu3/ev6Ah5/TnfxPIk/Pe/HZPkxbYjRDmjAeUyxxRqmAEEOvmdERi1vkYe7g
         iyBUn4fNlf9nhV6tsQjzF5tUv1/f6s3BnBFebNP6WVAMZ+kf1ugw9pBgaUqQyjdciXD+
         I+mr+OA5z1BC8SHeyQLg+gEc7GUlB6fj51VfzePEEc0iOiW0MB500WnBrqJi3n5+g8Xm
         fS1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XhoWvj+H;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7690aaaf9b6si284358a34.0.2025.09.19.08.05.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:05:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-77dd76f6964so32026796d6.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:05:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0q48bz81QeZ48YGbdXBTbgTV606Svr3yaPqJEYt8asu+MO59ueDrXWjryTzU19gYtJ5Mhev2qc2U=@googlegroups.com
X-Gm-Gg: ASbGncs55E5ueJ7MjnZzfxATR2ETfMdOBzEXF1Q7zqcB/3wLV3NYvoXFxEDG9k9S5Ak
	jAvsPUily0lVaLFc2k5RRU2/r4deRuuaXXKigU5o2HANECHNEkukZCr+i1ynhgmyVVyrGhXchBe
	auv3GDNqOel/R7+a1EX1uCJfaO0Mmty6SidczvcIRyyQ7U2BL84vcITfNP1wWOLYyCpXQTBq8ig
	r5aIHONZ5eS3SHVXnNS6LW2OBPwx8Qsi7dbtg==
X-Received: by 2002:ad4:4f4d:0:b0:799:59d0:4e54 with SMTP id
 6a1803df08f44-79959d04f7dmr32751596d6.31.1758294349954; Fri, 19 Sep 2025
 08:05:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-3-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-3-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:05:13 +0200
X-Gm-Features: AS18NWD-UemVXeXjYD7iHT8a4re1Qj02r-S9mCoMAicLgtJfaZDLOjotbdftD6k
Message-ID: <CAG_fn=ULHR_n+w=apc_g8Pe+MxXwNnQiRjOTRukzEiSAFK7hOQ@mail.gmail.com>
Subject: Re: [PATCH v2 02/10] kfuzztest: add user-facing API and data structures
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XhoWvj+H;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add the foundational user-facing components for the KFuzzTest framework.
> This includes the main API header <linux/kfuzztest.h>, the Kconfig
> option to enable the feature, and the required linker script changes
> which introduce three new ELF sections in vmlinux.
>
> Note that KFuzzTest is intended strictly for debug builds only, and
> should never be enabled in a production build. The fact that it exposes
> internal kernel functions and state directly to userspace may constitute
> a serious security vulnerability if used for any reason other than
> testing.
>
> The header defines:
> - The FUZZ_TEST() macro for creating test targets.
> - The data structures required for the binary serialization format,
>   which allows passing complex inputs from userspace.
> - The metadata structures for test targets, constraints and annotations,
>   which are placed in dedicated ELF sections (.kfuzztest_*) for
>   discovery.
>
> This patch only adds the public interface and build integration; no
> runtime logic is included.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DULHR_n%2Bw%3Dapc_g8Pe%2BMxXwNnQiRjOTRukzEiSAFK7hOQ%40mail.gmail.com=
.
