Return-Path: <kasan-dev+bncBDIPVEX3QUMRBFHAYS4AMGQEVMJ7ROI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E4959A2713
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 17:41:10 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2e2d17b0e86sf1059692a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 08:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729179668; cv=pass;
        d=google.com; s=arc-20240605;
        b=hZOzTBMbPl1rsfdHKk6WJVdFjHi6OMhCo69o1zxFn8VSuXslpt5mkbMCvOdrfSmgKU
         v0Lu4ExN3sX6QJupBG1LORb9SHsJJ6vZOKdCEY+J0OgRmXhWOpPToMw58sIqQ+ANdica
         DMbUNoweXhE3ydLcQ6g5xF0/gku3ukegGO24UhRyOBF1/Y13oOgskN9LlgFF2uIp68Q/
         CNRTyOqIdqIpJeSFDxsIWW4zp49Wh784rGlan2TjC+xmi5F1su4a16zLSUrQ9UViVOKF
         PImBNdyqTG1U1IXNliXDkGKLW+OICaHCwpw5suv+vnNTbrzDfhGykLnAtJTnlN7woCZG
         JIAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=pn361kbu6I9m4TwlayJEfvNZQ7Nps+QHRp78pmApMLg=;
        fh=gF8ZUuiKASNS0DEb4GhrJBYpAdAaReqaL9IFHNCXPSc=;
        b=DiSRTkONoY24hSfacD3eGP9qOJ7PYApz6U79NDmTU3pJV+2CLcELj27x/XMsMJysVm
         XnwrZsDqgdSwOAYtvj/TGvWSKNa/7x/pezKots294tsLDJIAQ0JVQNb2WDd0U4Ri0ru0
         R7/+NF2jKRTzspysKRbdUBppu3YWGXDWjS/lLXj4nTq6iLQhd27ppJHJeZj8Byp+9LRC
         yQAuG5XNATj340THx6a7ewUV9p7KG604u8x37K7TqBR0n5dIbdH9+LCbpywvF9WrzukK
         cFiir5XD3n0TJfBMQi+LSi15ObcCMlkuyiMG2gH9/ctZlpB/4C2EtCKQaTjKwAoyik4c
         mcBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=q4+UuIux;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729179668; x=1729784468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pn361kbu6I9m4TwlayJEfvNZQ7Nps+QHRp78pmApMLg=;
        b=O6iPFDy65mdM2ZEc4bYzYb3CN0rzk27o0Mc/vbasiqaU2sVZGAkMQCElirDyRpZBFM
         q8Lwqp6H4uQ6Ab0O+4GQ+QQoiLtNhxEJvY4S08cbwxxW2dvMGuXYOcjdEHmQB/8kLWko
         KQS3JNR+Ldbqw3O+X4m2q0xeYR/X274GBXxB2O6nd2HFT2sUzQuNZDqk8FfUc7YhsGTZ
         qJKJc0a+EZhh7bxjVg52Abe4EeUzmK7UwAlO2d2oauA33ffHcgGsXXIYCmxH6j4uED05
         QmHQuw71dUr8fY0WXYIjz+dq023ozpA4aovPbF4YfTXoGVKqSNOBLlyAZWZM1zpJuPSa
         RbVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729179668; x=1729784468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pn361kbu6I9m4TwlayJEfvNZQ7Nps+QHRp78pmApMLg=;
        b=KTHWJCz6iZyWN2oInBp3raCictrKJrhEAT6Z1xlYdQ4dC1GdSCGKpqV1HO6mMq/T3p
         59OtJSLsaY/jPjGZBHlAA2VFXfbZtscxPtbTswQBprpCe2XCd9c9ndIgRqNxLthTSISU
         edLZFHp1Kd35LBrfBAz4cdc60KOJAtdS2IuxJ8CNd4XWqEAW8rxwQPAggiDkWxQix+dE
         b8YFlCmmwP6gmzkilX2xbtxp8VwPw0iImN19z8RItx4T9RIBmyW6bEJr1jRTAGyCeG3d
         VZsbQ3zxi6dQjTb1vwKqEyzgPmbEGLV34ktjG4UGesoizhHelFBHDLRX/l/d9sKx4py2
         5WSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrR3n6R5X1yxC9x1ksbIynZahsGoAjr040qaFviClWyFI3opTKVb4ctri48psmBF5Wn+NNHA==@lfdr.de
X-Gm-Message-State: AOJu0YxGHhyPV/BHymw7RzXIiqUql1ya/nFskYa7PSfN31fZp7r9kQSx
	QQUMhqDB6xn6bDk9/sLZjdxo/tTgEJSJhTsmn8OM9GmiUJHvlFJ4
X-Google-Smtp-Source: AGHT+IEhM0i/l2aISWjY3JggJNyMHy2lM4fayjPhyoLfp76zbJjP4DFzEXOhoA33EQ3+m9C2iJJNWw==
X-Received: by 2002:a17:90b:4a0b:b0:2e2:d879:7cfc with SMTP id 98e67ed59e1d1-2e2f0affbffmr24776536a91.21.1729179668347;
        Thu, 17 Oct 2024 08:41:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:de8b:b0:2e2:a2ab:516c with SMTP id
 98e67ed59e1d1-2e3dc1827f1ls689730a91.1.-pod-prod-02-us; Thu, 17 Oct 2024
 08:41:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUN9iYU6iRmXhbKSfoXp3IHeDpZbERAPUN4S8swCSwvlMcJ8+6D5NrVBGqHtrzcxORHz8o6bg/GGXw=@googlegroups.com
X-Received: by 2002:a05:6a20:438f:b0:1cf:2d52:415e with SMTP id adf61e73a8af0-1d8bcfb2791mr29996057637.36.1729179666498;
        Thu, 17 Oct 2024 08:41:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729179666; cv=none;
        d=google.com; s=arc-20240605;
        b=WtlW2PEP0Uy+buDaC4aogNfoYJ1H/LqTqD0g03C3HqIQYP+BIS4JwaCjrdTP4Pm4n+
         crlYf1nifIQ4RNmQRk9Od9wOUdTwab2UEHKtqLYi3uu4q2AINDV21cQJ1uQWExjQ8FrU
         LmicNv0n9cf3dWPGuVuyC43GYJB4os2yM+YG1XU2623UM11ESgxQJngY2vgqxBFA+uZT
         6YC20du0jTlqoRVvlwJTJ/gHbmICl+ZooNX6PY7dehAJls5JSYcXdO+QINQcrE6pmYuj
         OaRgGJWR7SOyO8V0eIfBvqLQYZ1E6JLvhUN3+eAaR0m108s3d+WQP2i0Gf7utb0culH3
         dBgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=2vTKYvDLIpk92xWltrYyN1gsLxo8fC23LDEQoGs8f8g=;
        fh=s0EDCxZThEDCj2R/RK0unf1nsOk7py9PpxlLnYB1Bj4=;
        b=eRXOm2/Z8k2yFahX9rer8pWx3P3bNbsID7wxXxRAmtgKxF7bRpY1Abpb9frB7zLrou
         /pMwFE57NvtcQknnFc0DlgJKTC3Ivz+ybY64Y9vSuciTRpzJONRTGce3GGYWsvnfy5zt
         OCmVdO8YUbbINxxVkzSvRk/VmZALh/zh7vdH3LazUxDqyEwTmSyn1tpWR469Jv0o4Tlh
         Bz6YH1MK5HvRFNz0hC9+hDBqrsXKOn1Iwx1YXkG0DUIM8QyO/bMhxIzZ3JVKlqZj2GVP
         h/Hvua8/gUbqiCdKo0pKyX3myqA04ef47ceRyOOLpEEEu9GYEXbAWv3CqjInk7T621ni
         8tKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=q4+UuIux;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lwn.net
Received: from ms.lwn.net (ms.lwn.net. [2600:3c01:e000:3a1::42])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71e7747ddaesi250358b3a.1.2024.10.17.08.41.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 08:41:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) client-ip=2600:3c01:e000:3a1::42;
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net AC72142C26
Received: from localhost (unknown [IPv6:2601:280:5e00:625::1fe])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id AC72142C26;
	Thu, 17 Oct 2024 15:41:05 +0000 (UTC)
From: Jonathan Corbet <corbet@lwn.net>
To: Haoyang Liu <tttturtleruss@hust.edu.cn>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>
Cc: hust-os-kernel-patches@googlegroups.com, Haoyang Liu
 <tttturtleruss@hust.edu.cn>, kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] docs/dev-tools: fix a typo
In-Reply-To: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
References: <20241015140159.8082-1-tttturtleruss@hust.edu.cn>
Date: Thu, 17 Oct 2024 09:41:04 -0600
Message-ID: <877ca63ffz.fsf@trenco.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=q4+UuIux;       spf=pass
 (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as
 permitted sender) smtp.mailfrom=corbet@lwn.net;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=lwn.net
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

Haoyang Liu <tttturtleruss@hust.edu.cn> writes:

> fix a typo in dev-tools/kmsan.rst
>
> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> ---
>  Documentation/dev-tools/kmsan.rst | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
> index 6a48d96c5c85..0dc668b183f6 100644
> --- a/Documentation/dev-tools/kmsan.rst
> +++ b/Documentation/dev-tools/kmsan.rst
> @@ -133,7 +133,7 @@ KMSAN shadow memory
>  -------------------
>  
>  KMSAN associates a metadata byte (also called shadow byte) with every byte of
> -kernel memory. A bit in the shadow byte is set iff the corresponding bit of the
> +kernel memory. A bit in the shadow byte is set if the corresponding bit of the
>  kernel memory byte is uninitialized. Marking the memory uninitialized (i.e.
>  setting its shadow bytes to ``0xff``) is called poisoning, marking it
>  initialized (setting the shadow bytes to ``0x00``) is called unpoisoning.

So I have applied this, since "iff" is clearly confusing to a lot of
readers even iff it's correct.

Thanks,

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877ca63ffz.fsf%40trenco.lwn.net.
