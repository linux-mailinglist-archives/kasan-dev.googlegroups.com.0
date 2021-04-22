Return-Path: <kasan-dev+bncBC27HSOJ44LBB74MQWCAMGQEAADC32A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 25EC5367E1C
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 11:48:48 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id r16-20020ac25f900000b02901ae74bbfd43sf3311608lfe.10
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 02:48:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619084927; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jtf1m3RHEmYJIpkIVeugtkOSxg4R84xeRyU0ygMOpdw/sz+N5NDdDJsqrlGr89iN0r
         inTm9b/mBiFAvAJ3a0qx9o99V3ZzFoPiMsWN6MGpfRi2CVsCwC6LigAk7l/1vzqxuu5I
         a5KHEE/efyXZtr3cW7wJOLbCsqJZZ7nIShCqrV1fbhmVCKuhBZVgut5jtGeJ6P+EbcfH
         jDeAyVG1/jPq6GjcckqwEpYvpN6sp/qYiSH5lp8oa02LvOZi1FAaS3cqwyMvRsqkF0I6
         JXEaqWpGzpYy+anJIoEbpQnpRZpFcS9j6mrbeu+Krwnbe6FAygct8U7y4BKUsfl0Ee2/
         5NnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=2VWlyboGqFY3B7ybyMtOywMWbMmjk/0Zoq5pyGGh64M=;
        b=jndlKJ6cSCbpdHqti4SnEy+OEzjE7qMDEGioYkDYI2YpBNbf4sG8LLTWo/WDr/Uure
         U2rvBNWCjJU9njwGFPa3/s7viWhAdvEDbuuW89FhQzaZzprtEMvdw4ItEk98HSvmefIg
         MNzqkZJDBafn+mO0mj3n6Rc7AdPj3PQmEf1tfWWsnFeOuaaNLgYh5kiis06stAlzWPI3
         CTGOjzZyRCTNXSYNurpkvcbOy3qBNURrMFkqY2yrYZI4eFuFIV4CEmr19MYdJZBND76l
         rFczuGtSA1Y2uM+2dbjUPdrtuEdCBy2nN+LScPq12VPifUotIwqrEz4PbKyDAH6031OW
         bUng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2VWlyboGqFY3B7ybyMtOywMWbMmjk/0Zoq5pyGGh64M=;
        b=ONNdgsp9YwsKAF4BSVRuMG7Ab249+se56nNK/PzZpEX5tOndGpKhTEEFdGtZauL+ol
         ZjGB2zrrQ3zcOxZjZ3EhsGAjIkbVjeVzgphHiNx18qicYDJNJ4+wOZaQHBXI2OIznCGt
         KQJC+w/yMLUTc3inOygMv5HdP3Ut5phNw017cdbH9Ao8BEJ0/TqPO5o9YiQliwFOdD5z
         T256a2xzPRMc3Ve0VC/FtoM+OX/LuxD8cpK2Ut7ITGPhJVK7gIg1VUWcSV3BBtsGmcUU
         u2Jwi1nPyu9p5d5e9FzG2LqI4ljhrZWG7Y0/M1FMw9VMWOvWhDnUxrbZKeRRb9GDZDS3
         VPZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2VWlyboGqFY3B7ybyMtOywMWbMmjk/0Zoq5pyGGh64M=;
        b=ER47yWRpYycgrW2Hjs0nwm4Ujaf++QJaRjbnE1KeAN1ifvOxytwml3lvratbwPSTfY
         emT5HBXOyHJWey88Os0MdLJsULhabie3TvPzFAg+8nGjIXxZKChVkYMGk7wUeldSR5W/
         wWIM2UYPp8lhqk60bmXCYN74MNev159rfhuCaRmHKbAZ3RjEWqTIxbtuBz/AROV0NAkS
         fCyqQxehJohbebm1mJVhOxwedkC3VnRclvssnT9z2BbTXHkOuAwMUTpcM5FXVJeM6wDg
         A9X6XACH062o2ZmAqEQRUlsvYyfg44E3cdqsJkn4jkm8YnVNUaNRCrC+yxiWQqI7x/+S
         yU0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D6hiW8wbWyF8nLWHV4m7uYCDnVMPg2C/GGXfUwzqblotzSu1v
	oyV3C+8pZ764gYDyo6B4/vs=
X-Google-Smtp-Source: ABdhPJx183IMOz3+on4UorL5IN1QOB6JZ8uAjd5W9dh5kRCv6puqi4Zei3ri+oH6BbVg9l/m6zdY9w==
X-Received: by 2002:ac2:5fa2:: with SMTP id s2mr1910736lfe.486.1619084927687;
        Thu, 22 Apr 2021 02:48:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6c2:: with SMTP id u2ls427879lff.3.gmail; Thu, 22
 Apr 2021 02:48:46 -0700 (PDT)
X-Received: by 2002:a05:6512:308a:: with SMTP id z10mr1969013lfd.15.1619084926696;
        Thu, 22 Apr 2021 02:48:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619084926; cv=none;
        d=google.com; s=arc-20160816;
        b=py0sZQ86NVn/l8vPqbgzE0s3FY0oeG6sP5iC7nexha7iEJ6RSqGmPxPy9MqmOpwZAw
         TC88+Mn8tgOrssChbeT64u69wWBidRGzJxEJ07yBf0P/9IwUxqcYP09BpGPWOyPK3oB5
         3N790Qb4+qTNbfQrwatI+JByGRfldJMQEMnxtYQ0Fchj61lXCwhx7nsXerE+DrA5Y5g4
         Nco6CyiUlnZzVB7F3jfuSQNX8iMFs4RQSxi3mIr/kXtENctWU9tiBcY6OI+8BL+K92kh
         r48+PylffaHZXIZ6qVmyZ/Odmd+2bL4zurib4qLfH7UHXSwGeSYCKXSiCDV7ibAffIv3
         IPlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=GPbXJZUIIy5QkB7NetoD10lzJtM9pJU7pxDLmpDJXMw=;
        b=esUE9hA9JNTf7RjNsk++/QSwyDvb95yeFlFfN2dilE+IjAKCs9GDibqy/XuAzcuHPY
         J4ASDbu0LmgMq2gVrAgRrYRvU+69L17KGsrAySKbz0OTra/jsBxRtasUng0qWRfKaoDt
         XrFQ+RPu/jzdZpf4qPIoq3d7bQhORaU+sE8RraQwLi1rLLqCDhldoUH1Kj5mA37/ri8L
         jfvaxQViq3udrqFKsqT6wnEpyWR+2bRFkYb3OiFY36Ebzsoi3SsjrnQSx3HnPlboq/+U
         5H+G8FzTDpdQPCsIJg+OCPeHfeWuo+3gC9UZIDvHWI8m0OSxzmxPA8ZJad5yEPsWNqM6
         ewdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id r2si341798lji.7.2021.04.22.02.48.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Apr 2021 02:48:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mtapsc-3-u9EizjiyOa6oT5HDclJV4g-1; Thu, 22 Apr 2021 10:48:43 +0100
X-MC-Unique: u9EizjiyOa6oT5HDclJV4g-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.2; Thu, 22 Apr 2021 10:48:42 +0100
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.015; Thu, 22 Apr 2021 10:48:42 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Marco Elver' <elver@google.com>, "peterz@infradead.org"
	<peterz@infradead.org>, "mingo@redhat.com" <mingo@redhat.com>,
	"tglx@linutronix.de" <tglx@linutronix.de>
CC: "m.szyprowski@samsung.com" <m.szyprowski@samsung.com>,
	"jonathanh@nvidia.com" <jonathanh@nvidia.com>, "dvyukov@google.com"
	<dvyukov@google.com>, "glider@google.com" <glider@google.com>,
	"arnd@arndb.de" <arnd@arndb.de>, "christian@brauner.io"
	<christian@brauner.io>, "axboe@kernel.dk" <axboe@kernel.dk>, "pcc@google.com"
	<pcc@google.com>, "oleg@redhat.com" <oleg@redhat.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>
Subject: RE: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
Thread-Topic: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
Thread-Index: AQHXN0MFjTlB/ZNe8Eu7kYRWV5A4q6rAQy8Q
Date: Thu, 22 Apr 2021 09:48:42 +0000
Message-ID: <d480a4f56d544fb98eb1cdd62f44ae91@AcuMS.aculab.com>
References: <20210422064437.3577327-1-elver@google.com>
In-Reply-To: <20210422064437.3577327-1-elver@google.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Marco Elver
> Sent: 22 April 2021 07:45
> 
> On some architectures, like Arm, the alignment of a structure is that of
> its largest member.

That is true everywhere.
(Apart from obscure ABI where structure have at least 4 byte alignment!)

> This means that there is no portable way to add 64-bit integers to
> siginfo_t on 32-bit architectures, because siginfo_t does not contain
> any 64-bit integers on 32-bit architectures.

Uh?

The actual problem is that adding a 64-bit aligned item to the union
forces the union to be 8 byte aligned and adds a 4 byte pad before it
(and possibly another one at the end of the structure).

> In the case of the si_perf field, word size is sufficient since there is
> no exact requirement on size, given the data it contains is user-defined
> via perf_event_attr::sig_data. On 32-bit architectures, any excess bits
> of perf_event_attr::sig_data will therefore be truncated when copying
> into si_perf.

Is that right on BE architectures?

> Since this field is intended to disambiguate events (e.g. encoding
> relevant information if there are more events of the same type), 32 bits
> should provide enough entropy to do so on 32-bit architectures.

What is the size of the field used to supply the data?
The size of the returned item really ought to match.

Much as I hate __packed, you could add __packed to the
definition of the structure member _perf.
The compiler will remove the padding before it and will
assume it has the alignment of the previous item.

So it will never use byte accesses.

	David

> 
> For 64-bit architectures, no change is intended.
> 
> Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
> Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Reported-by: Jon Hunter <jonathanh@nvidia.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> 
> Note: I added static_assert()s to verify the siginfo_t layout to
> arch/arm and arch/arm64, which caught the problem. I'll send them
> separately to arm&arm64 maintainers respectively.
> ---
>  include/linux/compat.h                                | 2 +-
>  include/uapi/asm-generic/siginfo.h                    | 2 +-
>  tools/testing/selftests/perf_events/sigtrap_threads.c | 2 +-
>  3 files changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/include/linux/compat.h b/include/linux/compat.h
> index c8821d966812..f0d2dd35d408 100644
> --- a/include/linux/compat.h
> +++ b/include/linux/compat.h
> @@ -237,7 +237,7 @@ typedef struct compat_siginfo {
>  					u32 _pkey;
>  				} _addr_pkey;
>  				/* used when si_code=TRAP_PERF */
> -				compat_u64 _perf;
> +				compat_ulong_t _perf;
>  			};
>  		} _sigfault;
> 
> diff --git a/include/uapi/asm-generic/siginfo.h b/include/uapi/asm-generic/siginfo.h
> index d0bb9125c853..03d6f6d2c1fe 100644
> --- a/include/uapi/asm-generic/siginfo.h
> +++ b/include/uapi/asm-generic/siginfo.h
> @@ -92,7 +92,7 @@ union __sifields {
>  				__u32 _pkey;
>  			} _addr_pkey;
>  			/* used when si_code=TRAP_PERF */
> -			__u64 _perf;
> +			unsigned long _perf;
>  		};
>  	} _sigfault;
> 
> diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c
> b/tools/testing/selftests/perf_events/sigtrap_threads.c
> index 9c0fd442da60..78ddf5e11625 100644
> --- a/tools/testing/selftests/perf_events/sigtrap_threads.c
> +++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
> @@ -44,7 +44,7 @@ static struct {
>  } ctx;
> 
>  /* Unique value to check si_perf is correctly set from perf_event_attr::sig_data. */
> -#define TEST_SIG_DATA(addr) (~(uint64_t)(addr))
> +#define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
> 
>  static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
>  {
> --
> 2.31.1.498.g6c1eba8ee3d-goog

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d480a4f56d544fb98eb1cdd62f44ae91%40AcuMS.aculab.com.
