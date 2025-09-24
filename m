Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB5O6Z3DAMGQEBC7WHLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 740C6B98F40
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 10:44:38 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-63038c9145dsf4348628a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 01:44:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758703478; cv=pass;
        d=google.com; s=arc-20240605;
        b=J6NDlqzKnQgQd+AlPD5cZ80SZs4KwCXlikjs3q9rY53lkt3im14eSJftjr0Nem27VE
         74f509PPQpYGyYgzbTLLBfRRnm6T4Xmvd94YgpjbXUTWxuI1eDvigAmK4QMvdEgAZb0T
         hwrDimDJHuO7vDcDdT9zo+uNBAhzmhm2rromSQnldpOvFaqJDeq91a8g1vY2X5LkqIQA
         j0L/wKWULxrRgPOTnwsnZtPo12Pl/NvSIX1QXBLgGchedt62JTsMnwHZjNHmrkY8nc4/
         39kB5YqqQS2lJhjtmTEdwC/2ug0UtcA/vn3iNYg95HZWRtJSax5jGQkW+Plz27OqyJ+y
         UVyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=q7RzzirLtqkFx32zcCIFBX6KvZxuK3oaddvpKve/xJM=;
        fh=rghpf2TfIV9NILmddbH4lePbJ2kkpuO+F1WOOX3o7r8=;
        b=iAWQQPM+Aiq0Q776+fUUWH20crivqnwiyPgtiPAyQvduX5w/no68hYy2sQhw3u1rOc
         a9SDK/QoqGRjlQQlME8B4JdUyQahfIwbYACigIyZB8oUp4vi1oN58H7HxJvuWWBIp/Uh
         ugEiH3TJxHE7tuc+h6a3Vapm6SoPTnmISTtUybIwYej72/k7m+qW3sB8lPBOtyXBSJK9
         UL+dth9NVZ66Dfoe7+8UPhIdXKhVX2kFu2uVfS1LwqVx0zwtA/pAGWUUwNodIYKPwwpe
         DbiZjWKsnAD+5qo2dY/rTo5H+KCwHD10idiXcxbxuBUFfqTkHtKL4jO8BVIcdxbXa03R
         uvUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=qR17QMDU;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758703478; x=1759308278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q7RzzirLtqkFx32zcCIFBX6KvZxuK3oaddvpKve/xJM=;
        b=te7488aDLFOwxs6uS/deaGUag1/jE4Hjsx5JTzoKKUAeG7ntdVsB+h4YtIRP0jI3bw
         tK1jQaBLbv3BZa34D3O/N9TJ2xi69JkWdxWdxi56iGjQnOD7qD7IyoJChEenp3zre0Tm
         2QQkp8zcmQ3h3u/Mzd8dQfnonXj+dEazQvRIKLSvqZDiEsYGXL6hdPqqO32S2yTnXWaT
         7FRmwyPWf7oL4KJ5hTVIMjcwym/cq5n/ZUN7cPc0lAU0F9mqHf8ewKqkYL2E+g29P29j
         VHQUfDNPZM/SWTn3b7rPr4vv2jQfjnUiBjykdI8Srfinz5KfjzApopKUk1e8ubkwyRnv
         qyhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758703478; x=1759308278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=q7RzzirLtqkFx32zcCIFBX6KvZxuK3oaddvpKve/xJM=;
        b=cCDb41+fVblfU+lscXln4eE4Lhxj2AFwEwuSvPcguy1Mp1EDCVF/idbDQgf7Oknp4Q
         mrx65e3DG7qTyCXNRAHQOMluGC1Bc6G6Eeh049j9OyzruHVDEqqW8teSfUDLuXeMTLDQ
         rTMBQr+T6/p22McLm2C4NvyPc2QJB5gQwiPmEa9xi+us9ean0Knwm4C8GrAfC7FNT4RH
         qD6ROdB6UNvLdgMa1gBfvjsTUdQRPAMpyPATKnKCwRuSWG4sc8764Mq8a7mj7JyRKLhv
         QV/ZHzN8uvjny1uHPby+PdlVrYRSPdYvTmSy8z4bmi2fsHexapmhpRTnnJsLQMOsaGLY
         lUiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWSVS0bAqOZUORt6k3lztkDQo22pS91yGjS6Squ4ebD0MMfSvyUjLEpg1bney8qT0xHBIjP2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yyy+mxN1Z3LIJE6dcOk0qU4BQlOospPXxwm5IVydotXnxKMpe13
	iCcWie2999z8iFzV+FKizwuNce3S96NlDaPF+0eXnsbMzTxZ6ijHI5XI
X-Google-Smtp-Source: AGHT+IH4vQsrqv40dh8aWjf2Sp0UJ0aJ+MQK3h/uKHbhJmJJMAQzhLDErimegsZA1Kb7ZP6MTRNADA==
X-Received: by 2002:a05:6402:23db:b0:62f:4610:ddee with SMTP id 4fb4d7f45d1cf-63467787ae6mr5018744a12.10.1758703477744;
        Wed, 24 Sep 2025 01:44:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5zZf2l9ZdkKOQWNuJOCDqXe5OcPaGEDqLNgxr5vpVq4A==
Received: by 2002:a05:6402:50c:b0:634:85b5:86e9 with SMTP id
 4fb4d7f45d1cf-63485b58c5els331779a12.0.-pod-prod-04-eu; Wed, 24 Sep 2025
 01:44:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUR97JD5AGjIsMfeuuXVung27wZkOtiNZ04ERXxeEEG3c8cR9heurEqmTZOjTTuSNJX1ti8pn3JuTw=@googlegroups.com
X-Received: by 2002:a05:6402:535a:20b0:62e:ea24:8a17 with SMTP id 4fb4d7f45d1cf-634677eb7b9mr4127277a12.18.1758703474716;
        Wed, 24 Sep 2025 01:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758703474; cv=none;
        d=google.com; s=arc-20240605;
        b=IpNrcQPLi4Nk4XWzoqv6E9OLQZz+uL+NOR6/RXS5XoCM+UuZVO4x0526IT7VThLN2H
         OTZJbZAt9isRIxtjka4g6qsIWT0+u6JFiGuVZc3J955yxjnNLuDBQJ+T+cSLHHFhzlj1
         o5LASsJU4DsB69VX5x5YvdYmu26l2IHkHyxnWo7MLPvT1yKB+MjqNkEwUQ28KCQR3Xqy
         EX/iFtCO/RBSBWnirbGl6o1s1CNznPLUcWHlGAm6ACcQ3DEq7Hknlcdc+atOPn0eLTKZ
         qiy5VKeN3hHd8RWTPLLYynBGBcAkw6fxiYlg0I7jbkDWVoibhojfqLzRqZPEBJEVmpmo
         559w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=7E6QK7pHBc6Tj/OKkybEC4KJUY708g6FvcrorHKD8Ws=;
        fh=gZU0QbOfDfUHA1yliJKiIafaMj674KUIe0ogWesOIVk=;
        b=UCn580SQb2JpkIHcxLHPeYAipYTjJuGG8/aLsDsKmQmqH1a8p62p2JOXI+Sbr1dCnK
         Ei/+V7kqQBSN2mlN9UDBm6qheO8FCs3Mgfsx+Dzkf+YWhkcjxPHAfdF9LIU5vAUnpl9s
         Y9W8sfrPco76oDi8fQ4JanuiSbBXhx2iyNCugbMXGgsKqLEOzPr2Y0kLRAetLBP3qRbt
         SKZwVR2xwEOBLggU1Ur4hDhUVM6k6DDBFk+uWbZcUbjHpwBL118xfbyh6NWzBXq6p/Yb
         ZSSPA8ZqlE7cH59uV7Lkb2WQrW6IrYmPxfx8BkQR4qCdXPcaOWinU/WfmEmcBVjx2qlR
         KGYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=qR17QMDU;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6342e266891si199369a12.3.2025.09.24.01.44.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 01:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98.2)
	(envelope-from <johannes@sipsolutions.net>)
	id 1v1L6u-00000008TYW-2seR;
	Wed, 24 Sep 2025 10:44:25 +0200
Message-ID: <8d2ec79561f5aa17403014a298bb9188f904e489.camel@sipsolutions.net>
Subject: Re: [PATCH v2 02/10] kfuzztest: add user-facing API and data
 structures
From: Johannes Berg <johannes@sipsolutions.net>
To: Ethan Graham <ethan.w.s.graham@gmail.com>, ethangraham@google.com, 
	glider@google.com
Cc: andreyknvl@gmail.com, andy@kernel.org, brauner@kernel.org, 
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com, 
	dhowells@redhat.com, dvyukov@google.com, elver@google.com, 
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
 jannh@google.com, 	kasan-dev@googlegroups.com, kees@kernel.org,
 kunit-dev@googlegroups.com, 	linux-crypto@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 	lukas@wunner.de,
 rmoar@google.com, shuah@kernel.org, sj@kernel.org, 	tarasmadan@google.com
Date: Wed, 24 Sep 2025 10:44:22 +0200
In-Reply-To: <20250919145750.3448393-3-ethan.w.s.graham@gmail.com> (sfid-20250919_165803_858771_D7FB8768)
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
	 <20250919145750.3448393-3-ethan.w.s.graham@gmail.com>
	 (sfid-20250919_165803_858771_D7FB8768)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.56.2 (3.56.2-2.fc42)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=qR17QMDU;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2025-09-19 at 14:57 +0000, Ethan Graham wrote:
> 
> + * User-Provided Logic:
> + * The developer must provide the body of the fuzz test logic within the curly
> + * braces following the macro invocation. Within this scope, the framework
> + * provides the `arg` variable, which is a pointer of type `@test_arg_type *` 

FWIW, git complained about trailing whitespace on this line.

I'm trying to apply this and integrate it with ARCH=um and honggfuzz
(because afl++ doesn't work with -fsanitize-coverage=trace-pc and I have
issues with clang right now ...). Fingers crossed :)

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8d2ec79561f5aa17403014a298bb9188f904e489.camel%40sipsolutions.net.
