Return-Path: <kasan-dev+bncBDAMN6NI5EERBJXSWWYAMGQECVHHLUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 02D8C89743F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 17:43:36 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-416259a5fe5sf2126145e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 08:43:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712159015; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fe1eEQJcFT3gffqkxboDN3/xhS1HwHswbS+hX6Uzn7AYavW9YB1WuZ4GovfecUGQKt
         YIAJ6vRJIzpoPka5+jjD1opww77FWYTqINABNgPb/YLA/8oMLLbISZiQWdldbvSVB1uI
         zMxgKwDrZc6a75RbmghSgUiuqmNmufJZSnX9Dst8AfTgF+gFmuS44Vp/+By9/it4EQ85
         3DVHUS4CtSw8cxMjKXSeqz0MvvfZGlABtUzUGt9EvmLOPOyMASEgHvbdIVieW+o3Q5Fq
         hEYc6MP5aeSftZRlyPNUXiPcxfKw8PZyRR/G/+o6r+8zoWmKirbaffDAsGEsl/GjK1R1
         uufQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=kSNt/ntbcly8+A0+y/DQhW6tMxho7CHOA3xDrg6VMhQ=;
        fh=3dJJqeEnWfi/iY6lgsBJuS6OmrcWR+7YhzuQ+Q4SYmI=;
        b=QmwxNBlH7wdy4aQbVqTfpzSN4qW+WLrsQ2ba7Ei/zJozj/89v8adMDU3wEWyNVGgtC
         atBNbvHyh+QMtLl8zqsg4w2Q9FtPoC8NCTEjBINRjd9fP9myvoefGbemyPH4P+q4edVw
         YI2exkcSPlNwFKf5WmIKKpOyXSmtXypECRGir5nFxp55S/h0i+WJpqpgSyTzRssBLGTX
         FliEr+C4lKZtKxfqAyYX1UGjM2y5lxXAHice7M/6mcfzpFufzMDZfVaziZPec6zS+8tO
         M8s7EE+w2ZD9n9GJaTg6FUbVnAL8eWQMAe1ByBWv0h6VKa7KeMaI7oVQn66RIx/8JhfG
         iP6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=sD3iALlA;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712159015; x=1712763815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kSNt/ntbcly8+A0+y/DQhW6tMxho7CHOA3xDrg6VMhQ=;
        b=bvPynuekqXBhX70yzFZMns2UJmKbkeY3EWylT8i+02TtoJy2rrMYvKfTWy59oB9UyR
         vf8BH6Rp/TcR46vaXxAyPLEMgq7bHJdH7IOs0OyeS1mSfrgoKxjoUj/ACLwT0AXjne8x
         sb3rcp72BwWJlxPpOhnrWFKvs4XSn8h3+uCTMML+CO+NowsffdTOcVzzKraV2ZgdEwX7
         qW8+Wjylha3+mcf3U7CqgrwgM793vEhYubNKL1hsTHCTiSPO1dNFu8Ffc+RHWwkicsv4
         Bt1O/FGLpp1x8xUei7MWxHPfmSUyxUofeQu9FuXRRgHm0lqVH1NN1lIZLeBJ+RJDLCkg
         LKTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712159015; x=1712763815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kSNt/ntbcly8+A0+y/DQhW6tMxho7CHOA3xDrg6VMhQ=;
        b=prLQ8xww2Fd7yHLQ/sGOHLWhV/SKWJ/fh0GGhc2eW+VzKqRE+s+R1BeDD5jvkNmqyP
         efAjO7VeotdWIAsPhrVF5bkd5Zb8ImaorKy3UF5eBozRv4IZx4qyrDCDYQAtkRyHJKfo
         P6N/ECQG8MZprIxI3tct78IcPLwekAth8MJFEuIOesGV/n1Fy6aqCz4oGSNVmULDr1IN
         sVvchJHuY8ntOBMkx5fyAlLBLaAr/IeCHGKaPLuPnFmL94judA7AiC3WQieHsjZOZvwh
         Mf8X6kgmL68nBOR7EtVSiNxRWBjo64HQZ+P0VB6bjx/UqMT/ScgbRd0AVatLoEE1otsx
         JTCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLRkrJoKqGgBqbxkvsvJNWNpQmbEdMeuvOfY00C5eLlzdeqmX7/jMzasxDWGnb+CwNjiD5ohGoSzrlTe1D+aMCHQwbzoyLbQ==
X-Gm-Message-State: AOJu0YzSXugJvgwGAtidqzMntFYw+B+yMB9bxVSOT3DpGRepWzqYvVWh
	QF237xhETxRXrYnITUGuHaAZQwfzj4Pt8V84vPaFOrDQ9ZE9kHMa
X-Google-Smtp-Source: AGHT+IGqKrzKgj6Im8Hpl5YWTMIJYNzxCw+Zm7icIscQLP/rCtoj8f8BgYgNyQ26igDAwmz0LNxbfQ==
X-Received: by 2002:a05:600c:35d5:b0:415:6afd:9ba6 with SMTP id r21-20020a05600c35d500b004156afd9ba6mr33943wmq.1.1712159014803;
        Wed, 03 Apr 2024 08:43:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5119:b0:415:58f5:5361 with SMTP id
 o25-20020a05600c511900b0041558f55361ls22614wms.2.-pod-prod-07-eu; Wed, 03 Apr
 2024 08:43:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWe5Mv8GeGcom6F7WyS9dkBcMXeACd182KnmqxPezWuklIEjPUdNLD/UU993PwwYOV+GMWHA9K8R2EbzHw9rlcCN4tHmZFc/iJNpA==
X-Received: by 2002:a05:600c:210f:b0:415:45ba:bf55 with SMTP id u15-20020a05600c210f00b0041545babf55mr10876wml.34.1712159013032;
        Wed, 03 Apr 2024 08:43:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712159013; cv=none;
        d=google.com; s=arc-20160816;
        b=X9DBKNu+JB8T6H8BouFC78vKhZIi6NKVPkYO3ngKHscZn/RR/nKdYpq3DSgMfb2fha
         ZtJ34Q1AJ7AH9jOee3u9jDygMEhltIzsAjhIzzEF/MmZevVPIV1XloUOxSY7rvVLViSz
         733UmP09Dm9UdAUr4qynB9BlQNQa0CY51uu3IPJWyIlv5B3BBCkGmFT3I1ZDU22WZJ5b
         p+MLXZy/EoZ49KRmyoLAt7smVaBIbALb8TrgFdXg80HOCdAMI/V+5vFRDGPGtt4ZV0+N
         oeG7Is+7WzB6GTIsfejwy0l89tC81/XpvrR9+PWwr8DWjUK4uNmij+349vuUgdyG6hBR
         Xr6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=0ZWNUC2Pb10IDRHFLsN4mAj14Fjk7lK2G1G9BFqCQx4=;
        fh=OuAojZ9XtyzR6STIF2qTI9iuNn5xasdqzotJ7hmY3kQ=;
        b=QhjNmeaGx5C4ej5CqDs4A1DL6cDK321ILCD4NT13zjgm0vKgHzUkKzomwQP/Mw1Tgf
         rIXIos70utc39DeIG5HaTLM34l6GBm9ge+Mqlj6AR453FLjlwJA/tEYKHUZaknn2wmWr
         gZevLbZoMkogLaa/meGuTuBR85dp7Q9UpMkb+Rz+o33dZQz8y9ki3ZjH7ufgdojDRNrW
         PQr758wjPcXI/v1OZePFqzlo7jN+iMV765QMxIlryRRLIr74kgKqUJsiATYPAc2Cxt+T
         xCkH6nAcmI+two+I2vJnhp9vq/IoqAV2Iyn+32X32owzCqFu3YFY+4f3qOlKXmltwLUp
         iDiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=sD3iALlA;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id fc19-20020a05600c525300b004156b688ef9si228753wmb.0.2024.04.03.08.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 08:43:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Oleg Nesterov <oleg@redhat.com>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>, Peter
 Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, "Eric W.
 Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org,
 linux-kselftest@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Edward Liaw <edliaw@google.com>, Carlos Llamas
 <cmllamas@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
In-Reply-To: <20240403150343.GC31764@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx> <20240403150343.GC31764@redhat.com>
Date: Wed, 03 Apr 2024 17:43:32 +0200
Message-ID: <87sf02bgez.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=sD3iALlA;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted
 sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Wed, Apr 03 2024 at 17:03, Oleg Nesterov wrote:
> On 04/03, Thomas Gleixner wrote:
>> The test if fragile as hell as there is absolutely no guarantee that the
>> signal target distribution is as expected. The expectation is based on a
>> statistical assumption which does not really hold.
>
> Agreed. I too never liked this test-case.
>
> I forgot everything about this patch and test-case, I can't really read
> your patch right now (sorry), so I am sure I missed something, but
>
>>  static void *distribution_thread(void *arg)
>>  {
>> -	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
>> -	return NULL;
>> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED) && !done) {
>> +		if (got_signal)
>> +			usleep(10);
>> +	}
>> +
>> +	return (void *)got_signal;
>>  }
>
> Why distribution_thread() can't simply exit if got_signal != 0 ?
>
> See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/

Indeed. It's too obvious :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sf02bgez.ffs%40tglx.
