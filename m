Return-Path: <kasan-dev+bncBDCPL7WX3MKBBJEG7K7QMGQEXXMCIBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9982EA8A393
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 18:02:46 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2ff62f96b10sf5342918a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 09:02:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744732965; cv=pass;
        d=google.com; s=arc-20240605;
        b=gH9044dYRPOezoFnXWTBM/3rj3bqeIjfx4sBQMNSrq3q55TEJ3k+zVQDtNTDi2gSw7
         S87TxcCLZ7oX1e4Tlm42VSovrzujf4W5cbpbJkYo0Qz3fUFPX5SsIcxTsu1UZhE6rQl2
         f8eyWokQE0dAlPpXkaPkGH489EukzbeLndNgNdh40irTjdtpHLpMT9mhzI0y0gdHC9Nh
         KFRNWTYnk0CiGagLc8OtA5jkaqPL2fw0O/mPx/p11e5JJWE+1WWLIpJneeePCydqzgfB
         8PAjfaCnS097YOfEEAfAqz/CtpSdgV4HxtXd0+wF+8+VMFeHCsutNxOiWFDHXFDqmynx
         RziQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=6mKJ/dAP97cQmAkNi8WNNEdczSXePnU1asDYYtS3YRw=;
        fh=YnWe+iayNXfdbyf4AevW69R83HLh/DLAJ7WlOd6veLY=;
        b=Xb9pJaLdEbeKuAKVS1CuD2yB7veBmmDC6ZtFAaAjIKAUqBzA8Ryesx/ZkRcisL9Gx5
         l9LZcR1yWpeM2NaG2zajGcFwh9fGOYktwkK4B+e1YvvZFQOssFpzeOepnaR2Zy1sOJQF
         9d/OxN2ajQyxGwhVaL9efPS522zFzF9o2zyp4myH8V+a7lyI+NTtE4xLxvgDL15A6fBP
         nr4hQXtpIik/asfx7PKwtl+fFQFF3oNGSgfixqTUH7w9dnoCmwxp5tZiMZmNRNalIXt7
         FAzxUdPoxbrMr58IxyibmI7w6EL7Mzz8TBlhgXyKBsPflGRg9sCo7mNgy1lEqz9+O0hH
         hAtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sjwoQVXq;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744732965; x=1745337765; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6mKJ/dAP97cQmAkNi8WNNEdczSXePnU1asDYYtS3YRw=;
        b=jZiGiUO8HY77/4l6365L6cLcBTrUbkjhsB7VZbPPlvf1L//bo/YkNZ6NOCTVZy4jqA
         ZqwH+65j4/WH4UipO3M46VopCK1WmJ/R0M6z4fZ0m10adp3sz7ari1qEB3+sh6TElbEL
         8zkwLjEv8d7xsp8L8hBi4ZHjbAVk/QfflehKxg5fVmqIVZoA8uBnGBQCEXBGQiKfu9Zq
         UR+n/A7eVCRySRBvl5KEwwNxZiGNx3CTwRW4qtiEyQCSasgvF2pnXW/VSDPWyFYdPKam
         SclPWVwvLx41JJMnA4V9CFGCg5nJy234MGQg867JV/a+LFSN1OG9SwetLN8nlwVlruNb
         /Ezg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744732965; x=1745337765;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6mKJ/dAP97cQmAkNi8WNNEdczSXePnU1asDYYtS3YRw=;
        b=ZwyelFf+y+IfQ95k7AB37Rkeos0TUFavBe+hB2O/s2TFk3o/ouDXMJoz9qeVEXab8V
         Q9XyQ3Ml0t9Xwv3pvbmSRnYeRyZ72SWKYgcrxiJrwXp7xDlt8kiTnvET54ce4nEUu1vP
         uZS8ODD/n7d1l6JD8LA9MJf8JZIN2AbQd3X1/esnKeGnCLnZfBc2ZB5qoFEERz0aEUKe
         fhnk7VYlDKDSNuSNe/4SpN3+9K4ThwYnmwx18P9LS8Mk3s1xYQi6UcoxOsoj6McyfQ1l
         /E2dII1ZfX25Lshk9m6sH3f8IIr144gy+xveIDyMtyI2GOfuxAKycz4dxJW8+bA9TMwH
         JJkw==
X-Forwarded-Encrypted: i=2; AJvYcCVpENQe0H6iR/ttT3m8cP1NbKZ4V+gzeUJJ4kkKnlM7v4oDZkjrXOyXlfZUqONRP1QD+2iyig==@lfdr.de
X-Gm-Message-State: AOJu0YzeCQUDZ7zEq51zA5J0H8+Yn9+cJ32H24FQWUWWxyIuKapUY8UU
	ytyXiGItLNSaWYWmg4pWmC1iSxSvHLhzhKdym/ZTeimr88leLzjf
X-Google-Smtp-Source: AGHT+IHC+23b2pxdk19zTOT70vouSq21dnySz4C+4GGOyZTDPkI9Z8Rzb0bcWiZwAzDL4bumA4Rnfg==
X-Received: by 2002:a17:90b:51c5:b0:302:fc48:4f0a with SMTP id 98e67ed59e1d1-3085ddc14acmr106161a91.0.1744732964654;
        Tue, 15 Apr 2025 09:02:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJrUHs93Uc9fGvPQBposzLFzIWzZfvo1RoB3MBoIFHAzw==
Received: by 2002:a17:90b:2dd2:b0:2fa:2eec:8898 with SMTP id
 98e67ed59e1d1-306ebfa75c5ls2332120a91.0.-pod-prod-00-us; Tue, 15 Apr 2025
 09:02:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdKx6v9jkStfjKTbv8KrH/3uTRbwFA+KYD6LBWy7MxGm5yu5JaAlNiq9clJCQb9vgA/VGu8LtD5Mg=@googlegroups.com
X-Received: by 2002:a17:90b:390c:b0:2fa:3174:e344 with SMTP id 98e67ed59e1d1-3084f3b3bffmr5727934a91.14.1744732961837;
        Tue, 15 Apr 2025 09:02:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744732961; cv=none;
        d=google.com; s=arc-20240605;
        b=c01AShHMpqtGGcWgSHZ3K+eZknLtqMaGTQ4CRHHIWyYCGxnnx0/XkGL+5QrfPfGaqI
         ukIYyUcsydQsT3m9Avg4NRt8M5iwP73pAC6F2YotrcFW1ilbFdYzb6NTYaX2xkzTU3PX
         xl7URquel0DKOMLQnu0qY9fLVfhkORGgcPSWuD24rdRg+GEg9JsLAYCQps/fAih0PXjD
         OHFL/D5XAXys/b1CJhDoeW2l3e9VFlXniOmZHVAcLYtUZ8hO+pIfayL2eLDq0abBfqst
         /V3E945XUJ22IxFPUv7P4+gCtUGcBoZ7lCgHVXtm/bZt0ymCVRpx9SSQD5S54LQ9eioy
         /RGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LTpI6AlFrEwMjUkpDc2Sf9/+ukkp5yi28EB/w4Cn2uw=;
        fh=r1RcCvkoFsYcn8C0RLWLwXJ+5gBz+U4eFka/vUAz4SM=;
        b=NsbBexTZo5QYBDzoaH7fdv9eWp1N8HUAmzo4rr9zVvWF4xMY7cdl+/JHv7swpX4Z6Z
         FbzGGPyf3ngrMi1+zypYHgLVxZyCOzap8I6/hfmCPnDxfgM03i8iAKbkAyjWyqzeKFJ7
         DmzsJgUsAReipyh0YDfRZzARmtRfUaHZK5KOafAPCqFZE13XlIK0djpH5/R6KC23YOl1
         AmWjjm5jSHo3tDwJpNgmX2t+QqfGMLuLUmreiTyr7wPE+Y12kseIJbT928RmWwUtLIKm
         Yk/0lYvfhDczA/AHZq5GwuZREnoUhrrF/Pjx5TGy6AFwS+UfJRuU50lZy7NuMj+pXoo0
         xdjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sjwoQVXq;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-306dd14e10dsi1178356a91.2.2025.04.15.09.02.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 09:02:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id F24B86115F;
	Tue, 15 Apr 2025 16:02:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 77750C4CEEB;
	Tue, 15 Apr 2025 16:02:40 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	stable@vger.kernel.org
Subject: Re: [PATCH] lib/Kconfig.ubsan: Remove 'default UBSAN' from UBSAN_INTEGER_WRAP
Date: Tue, 15 Apr 2025 09:02:34 -0700
Message-Id: <174473295259.3417974.16266823568790250610.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250414-drop-default-ubsan-integer-wrap-v1-1-392522551d6b@kernel.org>
References: <20250414-drop-default-ubsan-integer-wrap-v1-1-392522551d6b@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sjwoQVXq;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, 14 Apr 2025 15:00:59 -0700, Nathan Chancellor wrote:
> CONFIG_UBSAN_INTEGER_WRAP is 'default UBSAN', which is problematic for a
> couple of reasons.
> 
> The first is that this sanitizer is under active development on the
> compiler side to come up with a solution that is maintainable on the
> compiler side and usable on the kernel side. As a result of this, there
> are many warnings when the sanitizer is enabled that have no clear path
> to resolution yet but users may see them and report them in the meantime.
> 
> [...]

Applied to for-linus/hardening, thanks!

[1/1] lib/Kconfig.ubsan: Remove 'default UBSAN' from UBSAN_INTEGER_WRAP
      https://git.kernel.org/kees/c/dcf165123e7f

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/174473295259.3417974.16266823568790250610.b4-ty%40kernel.org.
