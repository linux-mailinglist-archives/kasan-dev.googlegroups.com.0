Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEUUSPCQMGQEFTJNRYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A1CFB2CCB9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 21:01:40 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-71fb2ff16f0sf1454777b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 12:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755630099; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qy8X9I/AU/pUu+KXFywywmS6xjNnsGc8DHK3RkwEumdKEUMyBubhZMkZLJ3WiTYLQv
         jlL/JFytyFEhlvMdNpgba42GqtlWaxND+90zgz3YZrXqPbCXKtUPyqw4Wo8hml7BML3/
         2kX+UMvPqY+weCqF9zhEpBgFt/59XDpq9aEbDYtBENab0svKSDsNzCz1qpDrlVAIcA3N
         9pcaxL6KgOkCr05/TAOyom6GdVk/od5v66WmsT10tGoBsiornZyepEs/C6fI1hkitGB/
         /YcNvWvkv/ag9ivHJoOpZTxpnsMHPvN4Tsj8zUQ8t8kvKJIIJ28gd/ce2Iu3aU19te9d
         E6vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rz4uvvobIMKIlueuxW+2vC7aSBSS6CFBwkUh6+USIYg=;
        fh=do34okSIA1mPxcoxgmFt3aeRCuV9mtbTr17ihE6z4z4=;
        b=DVeKwgWs8CXbKIARfM3ZNiRJfjD0h8HaZNT7yg0uKx/DOat3SpiYJ7g1HvONtBWLh8
         bDH8vY9Q+U7+FJxSafarkuRLlgbDu5Ixidki9mHOxostM9vN+87KlcZ+LViS9Pu4tz/c
         rvjGJEKVETFMq/Wym5VpLSpUqaeXLiOaMcwnX8DcURhzPP+ESsLDjY+Cl/bYqAtrYC9o
         ANuhf0uiweFA6cKdZhM+mECiBoGqaxWkaBpR0vcTNLmPQwpJ6whUWA2YqF2JYedOMcYZ
         x9NHhfptQ5IXiSkGNl7A1iRr6J7smid+Ph8fWEljz4caw5IsJU+SHqpxcvHbz0c/1AJT
         LxVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p9Pm2oiM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755630099; x=1756234899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rz4uvvobIMKIlueuxW+2vC7aSBSS6CFBwkUh6+USIYg=;
        b=h7RvYaJI/n9nFm/5MyNdovM0FjOpDrlzKKC0EUKbU/Se8udJncYjVjJkskzOdMrn9T
         A8eIJ3ol9rbFeDBtNn+qjkgwmt5EgBdcj6OpZ2ALVohK3nGCAzXri6tYsP/KBL+on0BC
         tyW6I9MqcEMEZvUBLntB4a0wKJkl3a461ODHVD2ySwDohLCWecpN5FBnCy9uYllwx4US
         XSvw9BheOnYp92BJC0rn15R0MrZRk1prhlyhARAuQnMRvkPonIyIVfZ1GXeV32I51R2E
         sPtldvYuTIv7vSmOODMiqoTxMmTUXBkyrZRKkTucnJNDO7ATYg0f1CuLsZlJLOQA9okJ
         lsAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755630099; x=1756234899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rz4uvvobIMKIlueuxW+2vC7aSBSS6CFBwkUh6+USIYg=;
        b=BMDeHK7VQVkx4M66/mS0R/GnQcHKHnTdWTQUWQYJ8d/D9y1A5eV02jMqX2bFlC8yad
         0MbnriWJEtt8e+Kx/X6OwQacHIISxQKHf4uD8gAzT9+u5sHj7DS6voOP1vc3/CLwCsAu
         TQe60VIqzUBOqyosaCwyWwxKOBRlLx03o1eB1A0+eQ5ySw8Xug/5/dcIe2Q7XZ/sD9GX
         x/ez4fM0rhrJ9YiTfbJa/KQXVovlm9Se7bcIha/swCnNcFgJ8jrZZX2naD/HXhfnzv/U
         5tCH2bYJ3yo3qAONJu14Dvgjlz9UFGS0m+OY/7vysp4ortuJ3/OCWdubxBVtqfKVURNJ
         wYqQ==
X-Forwarded-Encrypted: i=2; AJvYcCXI+i+Ql9MJLykYCdKzEH3BM88K7tqBHSwEt/apmWGQ88YE4vHI90VJLd162DPO6MsVifoNEg==@lfdr.de
X-Gm-Message-State: AOJu0YxZdR8jQfr4BNCuaA6+rXiY4plGxgOudwZufgMkwRZx/3r0ypIb
	xJ8R7hP/TG+6obyjkqzaEBK3VI165WbPt3+ZbWypNWt6cUoEPi54gaOY
X-Google-Smtp-Source: AGHT+IFNGfxvzSWSVCj0WggxgPgzPoU/V/2vm0h8UIr0apPyUj977bl4AYS+gi2ck7VE9Kh6jn+Vaw==
X-Received: by 2002:a05:6902:c0b:b0:e8e:2368:d660 with SMTP id 3f1490d57ef6-e94f664b85amr238441276.34.1755630098212;
        Tue, 19 Aug 2025 12:01:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd12iIhj79hJT9c5p5CCCKj4DqXtwzdYN3+ocIBJJAF3g==
Received: by 2002:a05:6902:6c05:b0:e93:3de3:82c9 with SMTP id
 3f1490d57ef6-e933de38778ls3424517276.0.-pod-prod-08-us; Tue, 19 Aug 2025
 12:01:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU47e98yf12F9/Ky5pmSCLUCgbN9PdVhxQibvVPhpPkaO6sAVd6oc5ShOnQszWLtgleTp2hR4R7Wbg=@googlegroups.com
X-Received: by 2002:a05:690c:6d02:b0:71a:3698:b8bf with SMTP id 00721157ae682-71fb312d001mr3135657b3.13.1755630095673;
        Tue, 19 Aug 2025 12:01:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755630095; cv=none;
        d=google.com; s=arc-20240605;
        b=DUp+0a54k1uvbIgd+qisv4TbE8qdDp27rP5ISlJZ9tE3Z1m4cd5T7470u5Pp81aUNx
         3ugIMp1xwFaNBs1Rs81GIZ99ZbycrajfmEaZe+6yyuNxTIRwezf9kAN3e4mkOYRSMGQc
         1TPvr6i4E/IELSHIAWA97OaGaLhMWt2wKcCQIbvARELTIFt9CUpojyLVD/8bpt3vmU60
         Njmpjch+v3K/tlDOQa/On2un6h7i093UBNzzp7lUZSmH7ZN2elIfdCBTnsTKYY7XrNK/
         2ClTLXaLLy3CdDd/hCgE/k+hM2uN6BHhLpolhiqblKii4jeXqjKmLPzzMHLe1aGyK2Kn
         0m9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8qvuArYaZMFJV1RHzhtqqlTOKt/BCHit5YfuHRk9sg0=;
        fh=4pVIwmKRqnrQR4BNeIDQrH+mwnWFDfSj0KfgmdJwSRI=;
        b=YnYR2YjRiQTrF5vRAw1tkcaTv21pRvnFt4KOMPZnUnL9hl8ePtIptzrWMBkFiuW5CT
         rlK/H6r/Ro4mpzFwQfz0Xqml3mZ/T7+jmVz02TGWYsfMw5rETak6dxERnZvEvnjQ9/xA
         kmjmFekKm0wA47xhznk8Ugr5BVsH6aR5go+B+wi4q7lajIBDPvOR7T114mzu3Qk4IpAj
         saKxog//hegBwIteokJ9/craUglnPsWUTZ8gorUN2dvC8MSVzqY0PZlSbT1diciPDfvS
         emTBj3/WgE6I1cteXQe9cl4OAPRpbeasRPt/cdg0D1z0xdZKK9eWdx7p4H1V0nX+g5Ck
         RU7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p9Pm2oiM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71f98a4cdcdsi1344027b3.4.2025.08.19.12.01.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Aug 2025 12:01:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-24457f53d2eso69084075ad.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Aug 2025 12:01:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXcHJ3TVaeYfKv3UCqMfN6lqZHOBfVBgPEMmadCAnejUCaPvHPf6TLbEM8txGThmalW0B4d/2NbKSU=@googlegroups.com
X-Gm-Gg: ASbGncso3go2oLln2Y10SaL75zem93M9h/JRwhRtEoDCUb5qbamN9InCDrAAWnWdaou
	VBotSI1mn3fRhNkl4P+U0HEQIz769iaODkdjTuh2/+26fKGyhWRg7xw5TEiLYqQzh45vWx9JMd6
	0m6rg9UDJxunVHi2cFORFiT3/vX0D6HV6WPdu2Kh5JnLjC4wbxES8STPq+/e2VcNVvgbBQNH+EN
	J6nj3Ghp+4jYvksWrYgNccT7KMAOzeQae/oxkNV9DIt
X-Received: by 2002:a17:902:ce01:b0:235:f078:4746 with SMTP id
 d9443c01a7336-245ef25bb33mr618995ad.42.1755630094952; Tue, 19 Aug 2025
 12:01:34 -0700 (PDT)
MIME-Version: 1.0
References: <20250815213742.321911-3-thorsten.blum@linux.dev>
In-Reply-To: <20250815213742.321911-3-thorsten.blum@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Aug 2025 21:00:58 +0200
X-Gm-Features: Ac12FXwZea5-tAvhMnunHuHJNaxPoH5DoA6U1F3MtQeyJo61FGS19PYEFJ-wqmY
Message-ID: <CANpmjNOLKQsVTvqV+OdMrNOaHoWnUq1TU-nTRBKGCzY87E7xUw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: Replace deprecated strcpy() with strscpy()
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Dmitry Vyukov <dvyukov@google.com>, linux-hardening@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p9Pm2oiM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::629 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 15 Aug 2025 at 23:38, Thorsten Blum <thorsten.blum@linux.dev> wrote:
>
> strcpy() is deprecated; use strscpy() instead.
>
> Link: https://github.com/KSPP/linux/issues/88
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>

Reviewed-by: Marco Elver <elver@google.com>

Taking this into the -kcsan tree, but might be a while until it hits mainline.

> ---
>  kernel/kcsan/kcsan_test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 49ab81faaed9..ea1cb4c8a894 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -125,7 +125,7 @@ static void probe_console(void *ignore, const char *buf, size_t len)
>                                 goto out;
>
>                         /* No second line of interest. */
> -                       strcpy(observed.lines[nlines++], "<none>");
> +                       strscpy(observed.lines[nlines++], "<none>");
>                 }
>         }
>
> @@ -231,7 +231,7 @@ static bool __report_matches(const struct expect_report *r)
>
>                         if (!r->access[1].fn) {
>                                 /* Dummy string if no second access is available. */
> -                               strcpy(cur, "<none>");
> +                               strscpy(expect[2], "<none>");
>                                 break;
>                         }
>                 }
> --
> 2.50.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815213742.321911-3-thorsten.blum%40linux.dev.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOLKQsVTvqV%2BOdMrNOaHoWnUq1TU-nTRBKGCzY87E7xUw%40mail.gmail.com.
