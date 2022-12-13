Return-Path: <kasan-dev+bncBC7M5BFO7YCRBGXN4GOAMGQEZDNHS5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 95A0D64B586
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 13:57:00 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id c9-20020a63da09000000b0047954824506sf3340508pgh.5
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 04:57:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670936219; cv=pass;
        d=google.com; s=arc-20160816;
        b=LbUoMgm+OGCIYIkATSpRWBkT1h/vJTn5SJ8tMszGirEaIRPVELb5fZgpk4gfFDuNd0
         nbJ4JVgpSDB4+a3VJNdUYo1Hewz9hfsCCdTTiZx6EiZq2ARaL62t3KfoZjwwldD/6gFo
         dBogDFH3Tdhl983TeHNWnloThQmInw/pUSgMh9NrxQVuTRGaZooOGyBxeEvKCcOZIqqZ
         y5MomvnKN1uwF8OiR4TvAOBEC4j131/CSB4Ma2KE8q76C03IpIQiDi6/pjBtXwRpxZoo
         4Batq3JCYx832ZHQ6sdWn6Wypn8KaZPNbelEicHvfkA1rmGGlHG6vrov9o5mDqHMWSTn
         vx6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YC/ig7zfu/JC6YqPdohlS1aTMq26+fCQLPaW3jaTpMA=;
        b=G+O0GdbrBwJRFhYL5F/vaWRpgFTkDfiOP81jE8uWjPStxiv3PswaY9plZpxEPXr4OA
         myJOm7FERYHqphe39VFKI3HZ453RBAMNQUf0l+GRIVMIZ83m6LLiOxfCxcJhjjlV80wy
         6hVg8x1bTGNEsryervTh55hMHSpXuf5xXsglDSM0+dxhHi53xw4uGlkhTod04AJjsWSk
         j8xW9OSVhMraallQWBYP2IHgYrmLl7epI4c1isDSuGXdVG68htqVBRl/PMqHTYHTRHZ8
         MOFAKjpgfDaanzpkqi5lfoK/+ULTWrZXN3SbUaGbrc5iIHsjf81nttbh4/2TzmD0/VSH
         Liqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RQdoSyaX;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YC/ig7zfu/JC6YqPdohlS1aTMq26+fCQLPaW3jaTpMA=;
        b=ZNNbKt5tz9D60BQ29VupU7xuMIMXsZJ3mP5YSHt5cS4Dv0aW2J6QFGh2wrTpIe/0CF
         wgaiewj0mn/WzdFETP5sIYmqqd9IHMLNlAn9R7uo2xyJOZkkcAMYl13C4wcC+fl2Rjbd
         TUd1tHIShgVPihyoQrzofbLAEMoe4Y6USkCw0MU04Ut/mSIsoqKtE/wzcVk0dstXVzBZ
         mh/6YFzRUvGxDo4tqYlG8JgeKUnG2bx+C7LiU+GZISXVhv6f3TPowOUGTvG0oKJUj4wR
         Yiq48L5zzrXURw9k+Kp8BBtO/vyBBrqkiZFJNZ0ecsnbmytRbLVin+eB3DVBPXefzTTA
         xg+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YC/ig7zfu/JC6YqPdohlS1aTMq26+fCQLPaW3jaTpMA=;
        b=svYBX6P4peCUiKJmD20IOh9ZAkTpkLFx1bqxKLVJxIsaxoE6lSh7XzSgVT4k9FzeCf
         IHgWxl9j8fFh9h37Di8RSjUSp+3pcH+nQ5SO8Es6TiwAJs8wgf1fCLdmvksS2sUxRFmj
         IJjl7dowXOge2dVr4LoFf1q/zFqgzET3l8C7pAp2L2PkjngKfMrW/jANHhmmEz2AewC1
         Zw78lYgb4/Ucel/yp60iA53Xye0kVLWhDsDlBKt0Ky/RGprfeii9xHzLQtT7FswUQL6c
         NE8DDrtTlTVfp0GLIu1ZXLDO1k7zi47lIw39DXOgxVb5BUK8yQenoT8UeCGaOY4VuFXb
         MgVw==
X-Gm-Message-State: ANoB5pnkAMW/lnewpcLqVoYSJD9OCDNmO4ZZdJg/sj4KwYm7r1kQF/c6
	cxnatWjxVxIRdEQAZAuvY0I=
X-Google-Smtp-Source: AA0mqf5lpWZomb50AGB2kCF6oG/lJ5oIxQ5Ei9UlFenn6nC7AlYCE1HMGTdZvpQGOxp9A+r9LisWAQ==
X-Received: by 2002:a17:902:bd83:b0:180:87d7:9be8 with SMTP id q3-20020a170902bd8300b0018087d79be8mr93515082pls.85.1670936218967;
        Tue, 13 Dec 2022 04:56:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a898:b0:210:6f33:e22d with SMTP id
 h24-20020a17090aa89800b002106f33e22dls20503806pjq.2.-pod-control-gmail; Tue,
 13 Dec 2022 04:56:58 -0800 (PST)
X-Received: by 2002:a17:90a:a29:b0:219:184f:c736 with SMTP id o38-20020a17090a0a2900b00219184fc736mr23453624pjo.48.1670936217911;
        Tue, 13 Dec 2022 04:56:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670936217; cv=none;
        d=google.com; s=arc-20160816;
        b=a6OUNbXyXH9kblUnvvh5sRKbY6VbQH5tjBnB2f8XIOJ7NErkTUWK1QwTnoATqV5b7w
         QrArwB2hPbpUWKld65hYdPQd0iI/lahoM1ojbepKh5CTWk7iZQpZJgJ3CAXwWnhmHGpJ
         4cqxHJTynigWdPf8Ggmr72BUFyTvnRGtXH5yfFzQVYpcoX2tjWN4W7dgenB1jaFClfFh
         SKV/8cj38OZTCGV/MnR7L09CV9DuG8HgwOJUi7z76NodVjHXtOSk29F41WXfiPFNb6AK
         Kiq8GYMrz7jzdRBKxIqJz/NHufN52lmNxATK6L0dHTrfy3aR2nMtlHxIWwSl6NzR1l6k
         FL2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Zg6I1Rrlyh+xThqvnqNkyosSyJGrep07JtoqWe7Q9Ns=;
        b=w0ounbHCct6WhDirbzcMDAtjiJdrAfWHhsTlzVTC5z5hvqKHu9IRWXeTerHCXAu4ds
         vpeHnSu4OptwivKG3TxDiJvwCXuHY4sQnZkFmZxcVaNxgVwr83XSR52hRi68lcYZltI6
         QZgtSJUSLVEKqE9aEmJsUFXhavhsWw1PdZLjhipPjI0psErZYJLU3Arzy0mRNO1jAEOy
         APGD5ADMGVxRLLW6LNgowMrYsmsiKhzmR30WrBLyD4NgnGJkct10IaiIi7IjU09jyViZ
         k4hsjWNPFC8ed3E8QRpGhin+k2nlK4L6Osdcwu5LaGOKIEt5YGdfwkrMJyaWOGuEIzgV
         yONg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RQdoSyaX;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oo1-xc29.google.com (mail-oo1-xc29.google.com. [2607:f8b0:4864:20::c29])
        by gmr-mx.google.com with ESMTPS id fy20-20020a17090b021400b002195f5f3923si58056pjb.1.2022.12.13.04.56.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 04:56:57 -0800 (PST)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::c29 as permitted sender) client-ip=2607:f8b0:4864:20::c29;
Received: by mail-oo1-xc29.google.com with SMTP id v62-20020a4a7c41000000b004a0a214dfbaso2335901ooc.9
        for <kasan-dev@googlegroups.com>; Tue, 13 Dec 2022 04:56:57 -0800 (PST)
X-Received: by 2002:a4a:37cb:0:b0:4a3:c0bd:5dbe with SMTP id r194-20020a4a37cb000000b004a3c0bd5dbemr8913142oor.2.1670936217141;
        Tue, 13 Dec 2022 04:56:57 -0800 (PST)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id j2-20020a4a9442000000b004a083b965f3sm1108799ooi.29.2022.12.13.04.56.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Dec 2022 04:56:56 -0800 (PST)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Tue, 13 Dec 2022 04:56:55 -0800
From: Guenter Roeck <linux@roeck-us.net>
To: Sudip Mukherjee <sudipm.mukherjee@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Linus Torvalds <torvalds@linux-foundation.org>
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY")
Message-ID: <20221213125655.GA3622514@roeck-us.net>
References: <Y5hTTGf/RA2kpqOF@debian>
 <CADVatmM4Xr7gKqkeNX90KjmhB-E6H8rSfsK_E+42wp8OmALbDw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CADVatmM4Xr7gKqkeNX90KjmhB-E6H8rSfsK_E+42wp8OmALbDw@mail.gmail.com>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RQdoSyaX;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::c29 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Tue, Dec 13, 2022 at 10:39:30AM +0000, Sudip Mukherjee wrote:
> On Tue, 13 Dec 2022 at 10:26, Sudip Mukherjee (Codethink)
> <sudipm.mukherjee@gmail.com> wrote:
> >
> > Hi All,
> >
> > The latest mainline kernel branch fails to build xtensa allmodconfig
> > with gcc-11 with the error:
> 
> And, also powerpc allmodconfig with the error:
> 

Plus arm:allmodconfig, with gcc 11.3.

In file included from include/linux/string.h:253,
                 from include/linux/bitmap.h:11,
                 from include/linux/cpumask.h:12,
                 from include/linux/mm_types_task.h:14,
                 from include/linux/mm_types.h:5,
                 from include/linux/buildid.h:5,
                 from include/linux/module.h:14,
                 from drivers/crypto/caam/compat.h:10,
                 from drivers/crypto/caam/key_gen.c:8:
drivers/crypto/caam/desc_constr.h: In function 'append_data.constprop':
include/linux/fortify-string.h:57:33: error: argument 2 null where non-null expected [-Werror=nonnull]
   57 | #define __underlying_memcpy     __builtin_memcpy
      |                                 ^
include/linux/fortify-string.h:469:9: note: in expansion of macro '__underlying_memcpy'
  469 |         __underlying_##op(p, q, __fortify_size);                        \
      |         ^~~~~~~~~~~~~
include/linux/fortify-string.h:514:26: note: in expansion of macro '__fortify_memcpy_chk'
  514 | #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                  \
      |                          ^~~~~~~~~~~~~~~~~~~~
drivers/crypto/caam/desc_constr.h:167:17: note: in expansion of macro 'memcpy'
  167 |                 memcpy(offset, data, len);
      |                 ^~~~~~
include/linux/fortify-string.h:57:33: note: in a call to built-in function '__builtin_memcpy'
   57 | #define __underlying_memcpy     __builtin_memcpy
      |                                 ^
include/linux/fortify-string.h:469:9: note: in expansion of macro '__underlying_memcpy'
  469 |         __underlying_##op(p, q, __fortify_size);                        \
      |         ^~~~~~~~~~~~~
include/linux/fortify-string.h:514:26: note: in expansion of macro '__fortify_memcpy_chk'
  514 | #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                  \
      |                          ^~~~~~~~~~~~~~~~~~~~
drivers/crypto/caam/desc_constr.h:167:17: note: in expansion of macro 'memcpy'
  167 |                 memcpy(offset, data, len);

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221213125655.GA3622514%40roeck-us.net.
