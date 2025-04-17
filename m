Return-Path: <kasan-dev+bncBC7M5BFO7YCRBZU4QHAAMGQE4DXPPYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DEA4EA910D4
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 02:42:16 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-73720b253fcsf143458b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 17:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744850535; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vj/aKf7PWWNZg6LCgsVTUU7CuDH6c71QAVYKaRGIaBAMVRwK/0Q4ua0HZ0Dbvq1idV
         NrdWWh9JZFqN3WzMe1qLI6yBBTai55evCIAKxMZsTw4CAw/xzxFCTPLGzwA5hDxaPYaF
         sz6sBSzR8QhRWHhD0rlPxnLnKJu/1gv+2MDNnyiA7HcYKInLaK1krf9SGSWRzRdEIdsL
         BxHg8NQ2yopi2SSeR9X9zcjdaUlc3GqASA52bBJVH4Um9aF9rEaw67q0si6+DUWPGg/1
         /e56FAFPMH22R1OaXpreJbCBUPGq30cSs0SEHCWFw7ndQ6xi8UHO77bMHJCwy0fbTAPI
         RO8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=mS63wKYQGLfEFpZfNqv2MWegkE1VjSxqB4TSfm3lfUk=;
        fh=Vyf/+AEDMn4BX8nr2ri6GsjUTNp2AoEO3un50aYKyb0=;
        b=dq70r1VtDcrW3VdZM0wyvMfCLO36WIVxk+4rWUUehLLvetP6ZJxbZfo+y7KBLi4KVT
         6/dAtJxd6HofQiMAY8Cyb/yhm9hlQq1cBrBtQjClsYaWPzpOJJbfZD7sImSUejE5MBJW
         vupegqQh7h9GooRjb1Kjh9xO9jfpwIqJy5QsJGM0CbWKz/LNw+L6qo/WgWR1SVwInChk
         j0zAU2ek2YTIazhVozDU6oekUKbgvTfIgoO/qAbCcKpZ+8w2x2wyPwa2wqBz4WLxkFFa
         +rMS4a2jzHyDcwwyGmnG7V6FWnwpox0rceUoFPnIZvbiLJ3VPPXzTwtmUTtJlzwo6DIX
         BHSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RD4mtiF4;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744850535; x=1745455335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mS63wKYQGLfEFpZfNqv2MWegkE1VjSxqB4TSfm3lfUk=;
        b=DkKPrKgxLA7t3JTvsmw1xeQbd10mtBI5iNE/pgpwIDYdHMUuQRY0eCrS7Dv4WEVrwp
         mX7TMiyMy0Zc9tRS8kUAO1Q1yXmPeR2YO7oJ5fDPcechR9j0jtU40/oOUU+hiDKEQVEn
         wQ0QlfxLczHP28WSn4x40YGpqyQCfIaL/fEx8NkSEPYqgzUttRUflwJok1D76cxvsRIO
         VASqY0uE3oThs+Jqs2LGRUZxEgdCpFfH6K2NgHWlwcmjVI/lEa0arW/gFGpoqyXEuqyc
         Lib/cJi2q7EmxQBgD/yU92LCGh+hs6w629e3d59BoojbM874aakG8DCC5pLtjv373kB8
         9c6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744850535; x=1745455335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mS63wKYQGLfEFpZfNqv2MWegkE1VjSxqB4TSfm3lfUk=;
        b=iVtHnMfbtcSq7ro6CdvrtKMujirTEs5dc7gXHVgOLH6pHoY7zFjKHIXNZmE/9L9tYN
         NAP9o3kRSWiByO28UcvEo3QQhjw4z+BKnuh7maArD+SAh/IH23+ZnONNJEC+UnznNAg9
         Nht49QIUEWjd412f25kzsFpgDRrRWKF4V3Hh4ZhtDdmS0c4zq61C3AqmT42OBsbKvoJY
         719kPGHyN78xr/fXwuImXiLuWunWHMjzFjkTbobSTWF+Br4GxHuNZBeOtdccqC0oKqdi
         ci5Df1WIS43b++Th6bqbYGU9idg+wULVQXE43LTAtQgENGRc2OIIq4sdXFXytiOGWlWi
         wZ2w==
X-Forwarded-Encrypted: i=2; AJvYcCXd1g2vSkgI5qPuVZy4Zb1ObaCEzOH5LGDWiazXH2aiaSeTDvju+N8JoqUm3AoReWnASk833w==@lfdr.de
X-Gm-Message-State: AOJu0Yys3i7/46wDIRqXXjA6TjiOiOd63FgTN/7y0d1EOCiP+AhvLnVA
	1YtZWjU59DkpVsOGWCBWsievWH+K9NstV6Qafdt35excHM2iyzK0
X-Google-Smtp-Source: AGHT+IFzNyiF0Dw01sU9RZJyUNAvMvqRhcEObVcBmUNFM7ctRIqNbmP2SGlYvvtPBO1nt6eJX4oZ/Q==
X-Received: by 2002:a05:6a00:4214:b0:736:41ec:aaad with SMTP id d2e1a72fcca58-73c26722b88mr5803961b3a.14.1744850534914;
        Wed, 16 Apr 2025 17:42:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJq923uURtcLbp3jG/rZ3OEL4oFFeerh6RzvYe3LTWaOQ==
Received: by 2002:a05:6a00:3a12:b0:736:cdfd:9229 with SMTP id
 d2e1a72fcca58-73c32b91b6dls370463b3a.1.-pod-prod-09-us; Wed, 16 Apr 2025
 17:42:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpQgXcO2TkxU23xPghiNg1uHBSwTzqtck0yiVVld4GlVrh062v+O0nrX++1wqfXD4a1geybgepXWk=@googlegroups.com
X-Received: by 2002:a05:6a21:7896:b0:1f5:8220:7452 with SMTP id adf61e73a8af0-203b3ee3f1dmr6595044637.24.1744850533220;
        Wed, 16 Apr 2025 17:42:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744850533; cv=none;
        d=google.com; s=arc-20240605;
        b=Gok5TimTs10iaOCgxu83PzY1OGQpE2f4xaxMvFa7Isfy6FDYpzIqEVzGUQuQGx6Oq/
         GIwaAUgOM/NqBtZu4qqkQspbD3FORhu9uFiDXL4swoafPYjzs92Quq45ukRDVFLRdFk9
         ZSoQBPWoi+y0NsSa8Z6fKmz9KDFMSvEERYN+dWh8L2HqdJWi16YSH+5a1wOPeCFHl8Jb
         yhafEIlUIgI0jRb5o4lGpsNMwiDmexED3YUgRrCZOa4zb0X8pIzYQ5tDJNkCUE7DZzoR
         h8rFg6TptGtzksmfyayjLeRGi5v8mCW3HvFkmAtUdZbqIRTHHlvRYkiUg3oEiqRqzqX2
         /eew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=3JzZW8Vec/M6PKHJMF8TNngqQQy5yNrBF4bogvL3NjQ=;
        fh=blTm+s/BDYQrcwfy+ZzKjXSccnWIIxhjx8muG98zIXo=;
        b=CMnbcHvE2wcrQgDYJNPHrqrv6g+326s2sCpCYZXGnDFLx/Rz3tUGJVu8TZD6dJv09n
         MpH2dQDVa5oi3Gf5QBENgulh4ZzocNH5kJ2wIgoPriEL0bza1+lrenOO6vY41g/dGzp+
         /EMcTjux0fGb4q/mkVLPAzFtEhCyn3YWD8ximZ5bNn1D+GQYtJ3QSnN5r9shNsAJs9p0
         o4Z0cpHkdXu9+GkGoDwbxmrQDu6E6DToH5J5svLvQXHnnb8U1JcIQ/FFT4bmsoZzepug
         PTrnqs/okq5bWrKY9GQx0kB5Qz1QSLKX1E9fMd2ty7cfSVCxZ3BLBGGX8g1pbs3R2jO9
         RTwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RD4mtiF4;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=groeck7@gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b0b2206a362si112166a12.1.2025.04.16.17.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 17:42:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-736c3e7b390so137718b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 17:42:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUdc05g63THHFJnz4kEMsE1jEvHRcH5E6nPxkD1QqQhL6MJ/ZR83ab5kI9qn1yZbz94Ag0WxP0aVp8=@googlegroups.com
X-Gm-Gg: ASbGnctPGEJ1LdJ4wanoFC3TQEJ1kKFXb3+8KcW8wOvRdYAYC8dqS7LECZFJnm6w4He
	Dk7dv/Ss8FytR7fLi3FgJgpy1cHntP3+7XCrEfTapZKfTSL6eck/YC3zkXnKM2Pav+6T2qakVg+
	irFEx3UUDuDFrtujAvftC86ANKMEhPClxl6kUbzOwJeZclbMXuP4wbCkx9fNCAz/7QK88dI+shB
	WbhOWVDQM032kxc57E6jjQt/oBMdGQw/YsAZTUslQxRe72xwwlL2+kE9LfOsyqZKqWrGN+Jf8lu
	HQsaTm4Rv5R4Ja9MU1mphNzr0JzBASJJgnW7UsMssoC5d7vAduU7x0EJaGmZgTwBt24eMkMB3tD
	ac5gO6X8XE2h22Q==
X-Received: by 2002:a05:6a00:3a06:b0:736:3fa8:cf7b with SMTP id d2e1a72fcca58-73c2671dbc2mr4679954b3a.13.1744850532709;
        Wed, 16 Apr 2025 17:42:12 -0700 (PDT)
Received: from ?IPV6:2600:1700:e321:62f0:da43:aeff:fecc:bfd5? ([2600:1700:e321:62f0:da43:aeff:fecc:bfd5])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b0b22216855sm1888795a12.64.2025.04.16.17.42.11
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 17:42:12 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <a589599f-e069-4aaf-aed6-5cc02b322f1f@roeck-us.net>
Date: Wed, 16 Apr 2025 17:42:10 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] x86/Kconfig: Fix allyesconfig
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>
References: <20250416230559.2017012-1-linux@roeck-us.net>
 <20250416170359.a0267b77d3db85ff6d5f8ac0@linux-foundation.org>
Content-Language: en-US
From: Guenter Roeck <linux@roeck-us.net>
Autocrypt: addr=linux@roeck-us.net; keydata=
 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
 mDW4+i+XlNFUPUYMrIKi9joBhu18ssf5i5Q=
In-Reply-To: <20250416170359.a0267b77d3db85ff6d5f8ac0@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RD4mtiF4;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::436 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com;       dara=pass header.i=@googlegroups.com
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

On 4/16/25 17:03, Andrew Morton wrote:
> On Wed, 16 Apr 2025 16:05:59 -0700 Guenter Roeck <linux@roeck-us.net> wrote:
> 
>> 64-bit allyesconfig builds fail with
>>
>> x86_64-linux-ld: kernel image bigger than KERNEL_IMAGE_SIZE
>>
>> Bisect points to commit 6f110a5e4f99 ("Disable SLUB_TINY for build
>> testing") as the responsible commit. Reverting that patch does indeed
>> fix the problem. Further analysis shows that disabling SLUB_TINY enables
>> KASAN, and that KASAN is responsible for the image size increase.
>>
>> Solve the build problem by disabling KASAN for test builds.
>>
> 
> Excluding KASAN from COMPILE_TEST builds is regrettable.
> 
> Can we address this some other way?  One way might be to alter or
> disable the KERNEL_IMAGE_SIZE check if COMPILE_TEST?  That will be sad
> for anyone who tries to boot a COMPILE_TEST kernel, but who the heck
> does that?

As mentioned before, increasing KERNEL_IMAGE_SIZE did not help.
However, it turns out that this works:

diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index ccdc45e5b759..647d4f47486d 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -468,8 +468,10 @@ SECTIONS
  /*
   * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
   */
+#ifndef CONFIG_COMPILE_TEST
  . = ASSERT((_end - LOAD_OFFSET <= KERNEL_IMAGE_SIZE),
            "kernel image bigger than KERNEL_IMAGE_SIZE");
+#endif

I'll send v3.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a589599f-e069-4aaf-aed6-5cc02b322f1f%40roeck-us.net.
