Return-Path: <kasan-dev+bncBCDO7L6ERQDRBTFMYSZAMGQEZ7ZMMZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 761FE8CEC70
	for <lists+kasan-dev@lfdr.de>; Sat, 25 May 2024 00:35:58 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-41ffa918455sf4657755e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 15:35:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716590158; cv=pass;
        d=google.com; s=arc-20160816;
        b=prxKtzp8u9aU5WsoQjH1uVEGs2oJmq2BT/iBQCZ5TPJxM59w/RyTFJ7JZzMk8kdwmh
         m3ty7FFUql603zn1MT0mNGYZ+F5VmrMtZ4SqBkd8kkyRQQMle651VmOglM0V1e0nd+OM
         CKFB7mq0Dfyrb6wpkwGSlhsQqkTLfg+ycqwksgik1IOa2bjoUEizGEFWk7A8Pq8fuu0G
         HDEQ3C+VHtVe/eFiUgDHNAuRpbv7VWVmQPTgAx09zyFH5ZfOlufm3fmzTLqsvcb8J5A9
         Rf4vJYAgR6LyOB9I0ztjJGbe/Q4HdZHPwRg25MivPKlJn9tD3EtSfeixKSOSqkejtAxm
         AFSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=uLpC2OPXsIRFi31nUnBgi+K6PX6e9I6O1mHkV/wj61w=;
        fh=SGSDrxzeuuMl41eBhjhwxIsl+IUDWBjcrGQgG+a9A5E=;
        b=lUZ/DoaXGV6eqcxtIJnrchSsjHkD4haZLUeQrww7xcuDH9pNEGJxZh/KabHIvAbhGh
         XbDmZgqdgfVmzxkxLvz9IgrDjTvbyiHN1L+dCNeSMW+9evU0WbAVyUSK0Hru/FkkWVoP
         Im5WKajJi6EpJtNzH1Xoa3l7IIb8T4s2mlb0VVW/LDnpnxGTdOCUiXcXpk8lPUyui9jd
         PzLZzr6tiWAzqpakkz0Ur+0H9MwL08qBgKNCIVe6+DSyEBJRG1mKvJoMj2Dhw2vqq07N
         fwH9n9l49xIPXIHFjCShsKJX4MIHUeTQYSzswLPuyNEpOntvl7aIVKb/jrsRJLblGU9C
         E+Vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gQmYU9Zf;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716590158; x=1717194958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uLpC2OPXsIRFi31nUnBgi+K6PX6e9I6O1mHkV/wj61w=;
        b=P/Y+Y6GwZR7RUtsl9OWIWsJuqFe2sRIgpYDUYaeU5nlQCl7yT5D0DisWFJx07OQhTW
         2Co+/9hw9UYunODj+tDOCrsUt8stD+tLzoALhpPGgHwWgfdlHFCNQVEQkkpfTWoOXqqz
         SHb4wplYJU1R96I/BJFrn+MOjy0i63nTiJqnyZGOTkoXb5wmJhW0zRwKiIxy+SFBI2jP
         ZWXWL4JaSmn46YUfOJkvC2YAlOBqDkqo86+RFN01C8g5caQ7cca3EU4z+drRVHg25F3i
         WQcC7pHtZ42wlfDIJrFUkb4sIXdVnMHPbwh2dl3qqEN1bnVx2zBM3hsL/+lX+eItpKeB
         +yKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716590158; x=1717194958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=uLpC2OPXsIRFi31nUnBgi+K6PX6e9I6O1mHkV/wj61w=;
        b=f1G0LEz37PpomoD/IDi4kAMZ9GFxCOIVpEbRCRgFxz9fu6ZCVHK/yebiYUEy7cekOf
         sanD2EjNcoL6NjZnIyoJhaNqvRoQAHg17b6XlL3xAH5/9RgEQqMor0sIkNP06LCttIJm
         YmM8+AYKVXSr9KuQBjXZ7jrAgnEg1VPGxeOee07+ilgC2ZeCDe0TDJQTZT945yJF5i8M
         6Nq1/uU3zdJSRhU/PlMB/vnOKhVpq58tVXK1FrlDzQuSIvWOMACFQ1OMLiuxi/81rOIV
         SGIbkVixHWIXcjMmEPekvvWeTl4Rg/yLaZHavrNQorQU/q80/YH3G5ru515/mvQQTpru
         Qp6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716590158; x=1717194958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uLpC2OPXsIRFi31nUnBgi+K6PX6e9I6O1mHkV/wj61w=;
        b=fYOGhuiM4E69U72iAgRLqwHcslRoESVcoYt8Q1+Su4wsbMsmVLfJOiWE9zwAlqiNIF
         fX1B87ujP/A8+1o76k3/AzGeEdxVLG+deZGP83Z2NWj/VDgrNLX+8ePFBCsngN+2yTCC
         Ns2P01qki2qZm1mbpPFKzbiZjVgeRGFkb+F7FgjyubLUuRLAxAURoHPXece4WAtv/3WZ
         i8py6sqJxMMpbEBD9wvukBhOEF4CZoveKqZPB0dg+eM4AuZLIv8tXfkQmRy9bW65pG7k
         IDMryy+Kfc5qyPWx4H4IAxcw3q4iHE8lMlwJTaJyMWLGTFejWohYbh0OHxmJct+Tr+Ti
         FMaA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0ZE98rrBt+1OJJO7GYuAX9X5qwkqCoZtbyqD0Ak0uO224xkZhKJzoNo51ascRZpzSL4BfTfImkv16oJ46ksPqJX/sqsPLQA==
X-Gm-Message-State: AOJu0Yyax/FlbJB86jom7jN8JrWGV6ZnB5AvsGG3k5d2ROggkhAoLC++
	qJWyWJwFIfOljhMP6+DIRBdwGeCSazrEHeirbuFVIgVphWEmjRjr
X-Google-Smtp-Source: AGHT+IGB3kO4bGKsnQD6sA+ogMQ/e/E8lMufPuf/6xqLKhjSIMKOYGbdboTyzIo4tQsuLD3XSVdG7w==
X-Received: by 2002:a05:600c:4592:b0:41a:bdaf:8c78 with SMTP id 5b1f17b1804b1-421089b2201mr31775015e9.8.1716590157062;
        Fri, 24 May 2024 15:35:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d1f:b0:41c:2476:c9b0 with SMTP id
 5b1f17b1804b1-42107c4709bls7312885e9.0.-pod-prod-07-eu; Fri, 24 May 2024
 15:35:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgVUMtpGu3IknEfPfG/zpLUMAHeld9sdIHppxJy3k3zBoqSkXrTsDWTWMu61Pwh1ALcq0/HdrjXaTC4Id6I3/NJCLDDQ1Bfk3T0g==
X-Received: by 2002:a05:600c:3144:b0:41a:c592:64ff with SMTP id 5b1f17b1804b1-421089f9787mr33352465e9.35.1716590155326;
        Fri, 24 May 2024 15:35:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716590155; cv=none;
        d=google.com; s=arc-20160816;
        b=uhVhG9qa5YAeEBRal79yrpxlsPEZidPoJFoiG3s7ulEhUkACXfSnwsdiPfHKOLNQRP
         zfUxg+LS4pQBckj3HPKloPL8GQ61l9N0m0408wtEaD4uDE60etGn3OiMl41OumX1Jkw6
         h77onHGOmRWZuYP7dUPpnfL20uyt1jMB0JMUJ3HFbqa85H1roOI/fTTdCUuJpnyb4IhT
         pi+XkGVBUQiu4jcT+iPaliJa4T6gcNQ7101rY90HzsmbhZBN7k9Z1bRMyBwpz9W7dWkR
         K467HQZS7J0qZd68wz9pHRexCCMYCRbFsFy6/3FkXQlo/MtuJ0By9+txcdRRFXF/3J5+
         5LRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M4VCk5Dt2iAzT91u/gVxNNQBx4fXfDo05VmnDW4PrRs=;
        fh=bAdpjrn3Tv7T8OuzswQLcM0noqMu7Q6ZHZhfarNn5xY=;
        b=CpLTY1VbwREzqYfuSNCwF/4k+hRVnSZVDkIV9dXkdLZJYRY/cjPvxx0dKoMZMLzIwl
         fe8ZYH50X5Wu849eXdhUftxKDf87+aMes/cIItgST48qlhxI+6SbFc3KLqBE/8VkCxrW
         uBN/HzfO4EPFXB7YJ9AS1ISfLR6e2OCJiHhQzndSQaecmM6ma8rF2YTh6HO6z4UM8htv
         sL1rHcJwLFynffCsRqYYmxvMtkF3bUfqdNeh6EjAxnYGr1G6jDQHvMh6G9qIAwpqch0j
         6qYxfRl17xt6YkOs2aQla9WlwF7HghExvAhtN3UaJrAZYdNxjM1kKj346EDCZ9I/tSsz
         p6zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gQmYU9Zf;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-355656d42b7si109893f8f.1.2024.05.24.15.35.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 May 2024 15:35:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5786988ae9bso121949a12.3
        for <kasan-dev@googlegroups.com>; Fri, 24 May 2024 15:35:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUG1hhoCWm+XenDBJUNenoK3kCPTp9WMoWM3hGXfwsD5zYQr8LPjWjJZoHMDPJJCAWk6NzQ8gNu5NT9bNGKwOEjDWelrlN/IAEF0g==
X-Received: by 2002:a50:ab13:0:b0:578:5d83:bae2 with SMTP id 4fb4d7f45d1cf-5785d83bf4dmr1949090a12.15.1716590154619;
        Fri, 24 May 2024 15:35:54 -0700 (PDT)
Received: from rex (lab-4.lab.cs.vu.nl. [192.33.36.4])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-57872da9dfbsm23821a12.2.2024.05.24.15.35.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 15:35:54 -0700 (PDT)
Date: Sat, 25 May 2024 00:35:52 +0200
From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H . Peter Anvin" <hpa@zytor.com>
Subject: Re: [PATCH] x86: kmsan: Fix hook for unaligned accesses
Message-ID: <ZlEWSIcHXnh/BqbW@rex>
References: <20240523215029.4160518-1-bjohannesmeyer@gmail.com>
 <CAG_fn=XR6KVQ=DbKZW3kNXsCHgULm2J7i6GCm8CZUjpjuk-d2A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XR6KVQ=DbKZW3kNXsCHgULm2J7i6GCm8CZUjpjuk-d2A@mail.gmail.com>
X-Original-Sender: bjohannesmeyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gQmYU9Zf;       spf=pass
 (google.com: domain of bjohannesmeyer@gmail.com designates
 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
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

On Fri, May 24, 2024 at 10:28:05AM +0200, Alexander Potapenko wrote:
> Nice catch! Does it fix any known bugs?

Not that I know of. Based on my cursory testing, it seems that
string_memcpy_fromio() is rarely called with an unaligned `from`, so
this is a bit of an edge case.

On that note: I tried creating a unit test for this, to verify that
an unaligned memcpy_fromio() would yield uninitialized data without the
patch, and would yield initialized data with the patch. However, what I
found is that kmsan_unpoison_memory() seems to always unpoison an entire
4-byte word, even if called with a `size` of less than 4. However, this
issue is somewhat unrelated to the patch at hand, so I'll create a
separate patch to demonstrate what I mean.

Thanks,
Brian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZlEWSIcHXnh/BqbW%40rex.
