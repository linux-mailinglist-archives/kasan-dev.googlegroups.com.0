Return-Path: <kasan-dev+bncBCAP7WGUVIKBB2MTXWYQMGQEV3Q24BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 443458B5225
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 09:19:07 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-36c1af8f2f3sf46490405ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Apr 2024 00:19:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714375146; cv=pass;
        d=google.com; s=arc-20160816;
        b=dARZV3lXUkWOFNk4SW2nU3rihdHcoU7TEYJIAZGW14ke3OFEvls7pF3yY5jlVBudEm
         g9Lyf34mZOE5vhhZ54XBSgQe0v7A7fma25iSKf4+TvD9/gCtQSUSH5INh3iNh8yMQQHG
         kvGIpw6f4PSXCitvpXST9ZnP/NvWAq+/Pl7MVGaRNXQnviArIK0cls9T+5tBWW6JdMb2
         jjrPp2EgOX30R9ycjqPD6cmq9iuR6egqplxyabeCNjx8R/+ASO2HcLQKQloaKMcOef/U
         Jn+DFK6dpxy4CSoy/w8Qzhd6Hni8ho7idWNpzcvJZroSzuKRe2vdL8GbEOJxN4AlP3Tx
         kurg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=DMSwDRpekdEuUaE8Xr/YBkAxKQdV7BXgvAJ7Z2BxjH8=;
        fh=vLTtg/EPobSRTmWgbuOiOqArgXoSrt7mJ1nS5gp+5e4=;
        b=Drx8FDAbtW122WkLrMQi9KihqkTIembso5tNb8ZlvRuxL2CmobqI9TgZen8piyvn+X
         s9+i88Az0ECXNasIGDp3Ce0zuWZ0rA4fxGfdqbmfQBeLeKYJmlxj0OJY4ge5fIdOTsUL
         f+dH6IppGhiv6p9ma5CQJpk9kRpTzpYbQyogpc8/cfcIysgeIiR2yaXHb7WYSLhtyq9p
         4GjR+NxU7HeDp98yDK885dwYZRB2dCU2Wwxy+Fa/jGKdEnehyRvKzJ51lCxlmWgDEJfq
         J7Ayy5M7rf4gUvbM/wyL8QeB52GGORZ12Aawe2ysmoo8uXOkIATqJ1deOQxghzgvk+1J
         /fHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714375146; x=1714979946; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DMSwDRpekdEuUaE8Xr/YBkAxKQdV7BXgvAJ7Z2BxjH8=;
        b=NJ05jrPnYcOxbzgBWvJE01qCClHLrvQS8lI5QGQRcP6COg7kn+GKDcJFG5XA8CdsT3
         oR8lgnhv5hN4acaX0wJzcNOabzXYHxX07a7m10SEkSeLwlOtu8IxwJl4W3wCu6eH6NCS
         qRMKj2aevQr/ghMUFnSFiKn0SHUqxr86IvfX8ct1HFmfQAp+/EgYGFsWiWU6jmHSWyak
         kFwTrdjBvnt2ZXKyE6pn9WlL1M3G2Vola1Lijs3DRkFgAhs9cN67a97oLcclQjyyqDft
         uh+p0l1W909zWpGo5CVkkk4x/itmthGKWMu2phqb7mQwdulxhL50Mvf70KcpMr2mtM7s
         iJuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714375146; x=1714979946;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DMSwDRpekdEuUaE8Xr/YBkAxKQdV7BXgvAJ7Z2BxjH8=;
        b=m8gGx+CL8Gg4P6FXpi2Yui8B6gbRfCS5u2p50dS12b8PuMCvBJOBSeQn5ecjHr4UVn
         CKT4FqlGpES7FyNGKuKXvW7FYlQyl829cqBq9KZiv+wKnbpHy7EGsC/vaJy3J8c4BVuU
         dgWRE7AjylrgYKJJYEjDDTlpcMK6FmdA6+pwKpylgNi1THHeK93L0ff+uGcsV5ksimfN
         ZgKTIBdZ5ASLCredxZX9euGwT4VK6j7mwR3rnmwunxuGURf93qZlHft49LIxe1YLyf44
         iJDAaYmPg0dMbmklrA9porAbvbOsNqPhc+M79XxYVr8fx5h0L05b6oP+ZWcb6N2iJLOf
         WftQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjYfOx+tP6kDDR3u4BvBtpA0yWdD95VlgQitnZZzJcw0Je05zV9V6kY06DzPsWcfeLTr3x586zLE51N3QIe5JNufSJkWv6Xg==
X-Gm-Message-State: AOJu0Ywa5YMg6xxay7Bpb0Qq6HtO+q7dwTe8nyVdjIqQzfD54oLL14/N
	V4yCMTHKVHGgGG+dqVUqWrEGo9oaoPlpxwOqo2GQEvSSDnbc70bd
X-Google-Smtp-Source: AGHT+IHoKSY8e4Jpg5NxgsW5lmzl8kfZv9k+toEeR0AssQR8PjNZaIZdamWZlG2mIaFzayjL5hnWaQ==
X-Received: by 2002:a05:6e02:1fc8:b0:36c:dd5:63a1 with SMTP id dj8-20020a056e021fc800b0036c0dd563a1mr11023685ilb.24.1714375145824;
        Mon, 29 Apr 2024 00:19:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d9d:b0:36b:31f0:119e with SMTP id
 e9e14a558f8ab-36c29d9c826ls16762325ab.0.-pod-prod-04-us; Mon, 29 Apr 2024
 00:19:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLo4Of90pxkv5TQjNfpQL1/Pc8UCG7w57lLRlzVAqG9VVeg1CGMFIk7EAx6zkvLMgIUqAHIXn2m92McPDOf0HZGsobvJgdw5xc5w==
X-Received: by 2002:a05:6602:1789:b0:7de:a819:6d76 with SMTP id y9-20020a056602178900b007dea8196d76mr9407456iox.2.1714375144640;
        Mon, 29 Apr 2024 00:19:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714375144; cv=none;
        d=google.com; s=arc-20160816;
        b=WrtAj1L1HwwBOzWFCU6xR7JR6Bm3DQW2BHINbR95npGED6XFAEkQxBUXF/5Tb9ETyz
         vsTDabh7SYCwr0pIe93j8iGBQvJu/WDf8ePf76+JxjvKqwh+njfSBqFfHdn/48WpAM4K
         931OQvusbE8YuDPWZUp6fKmJAp8isnC6W8RSz5w6LWdmt/0RxxeVA92NAeGyDJSCpvsY
         w6beegtMb2oXgbIwfJs3292YUGcg8cO6JC9GdbXMpBHgTCED8KdV6fnrbNGJHulg6Kx4
         fODURrlFMCqUx13wM4FxB/c573gDOCrSrxuYiyzGsTzMx0MZf1qHnpKtGqxZbfPobzQb
         ICzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=2pwpwyZEzjNnN+Dm2DuZ/h8dLGN/f5PTg6hAtxUJeXk=;
        fh=guupsp64y7MHxuoBl1ePP12LaSRN7DWE5paPxAxosNU=;
        b=kFc/g3R0zD/pHMyvr/qX3SkP+Hnr45i6kw9b8AHTZfj6VtomfN46nH9w52yQ2VfhwO
         gWodhMTcbaFe7euMOIsjviSme9Za9vWGajwyI95s2NTpQUIVo1Ee/ybvsAM1CzNlFXgN
         sQpmYq/ABUOh8JjOsV5wjAZBrR7N4Iy5w1KHD836Xa6o3nZ1V7RsmNM6JQHPhuts8fNP
         zb3BCwM4RosNGmerB2JHQmE04QD8+4Sq/4Gxgip60gITh95T8Rn9eRWaJjEMG4J1fGPi
         VmsKvB/AZUVOqmtAlCbZTU2yedLD5G8B4CJAbMDPavzvdhu57uRLfdVWuY5q26vgv6SB
         mZWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id w19-20020a0566022c1300b007da85bb8139si1116678iov.2.2024.04.29.00.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Apr 2024 00:19:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav111.sakura.ne.jp (fsav111.sakura.ne.jp [27.133.134.238])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 43T7IuXY012402;
	Mon, 29 Apr 2024 16:18:56 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav111.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp);
 Mon, 29 Apr 2024 16:18:56 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav111.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 43T7Iu02012399
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Mon, 29 Apr 2024 16:18:56 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <42efccd9-c066-4acb-865d-a96dade123d9@I-love.SAKURA.ne.jp>
Date: Mon, 29 Apr 2024 16:18:57 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3] tty: tty_io: remove hung_up_tty_fops
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
References: <e1fe6a44-3021-62ad-690a-69146e39e1ac@I-love.SAKURA.ne.jp>
 <20230424004431.GG3390869@ZenIV>
 <8e21256a-736e-4c2d-1ff4-723775bcac46@I-love.SAKURA.ne.jp>
 <2fca7932-5030-32c3-dd61-48dd78e58e11@I-love.SAKURA.ne.jp>
 <20230425160344.GS3390869@ZenIV>
 <1b405689-ea0a-6696-6709-d372ce72d68c@I-love.SAKURA.ne.jp>
 <5cebade5-0aa9-506c-c817-7bcf098eba89@I-love.SAKURA.ne.jp>
 <c95c62ba-4f47-b499-623b-05627a81c601@I-love.SAKURA.ne.jp>
 <2023053005-alongside-unvisited-d9af@gregkh>
 <8edbd558-a05f-c775-4d0c-09367e688682@I-love.SAKURA.ne.jp>
 <2023053048-saved-undated-9adf@gregkh>
 <18a58415-4aa9-4cba-97d2-b70384407313@I-love.SAKURA.ne.jp>
 <CAHk-=wgSOa_g+bxjNi+HQpC=6sHK2yKeoW-xOhb0-FVGMTDWjg@mail.gmail.com>
 <a3be44f9-64eb-42e8-bf01-8610548a68a7@I-love.SAKURA.ne.jp>
 <CAHk-=wj6HmDetTDhNNUNcAXZzmCv==oHk22_kVW4znfO-HuMnA@mail.gmail.com>
 <314a8e87-8348-4f40-9260-085695ac2dcc@I-love.SAKURA.ne.jp>
 <CANpmjNMx0eiNUY7C6t_Aay=QMUT6743axZB3wn06jL6Q_JTXOA@mail.gmail.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CANpmjNMx0eiNUY7C6t_Aay=QMUT6743axZB3wn06jL6Q_JTXOA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/04/29 15:53, Marco Elver wrote:
> Thanks for the ping, I haven't seen it. I will respond to the below
> thread separately. But before I do, just I get it right:
> 
> There is a real data race where one thread updates a function pointer
> and the other reads it. After a function pointer has become non-NULL,
> it will never be NULL again, but will only ever be updated to point to
> some other function.
> 
> The assumption is that both read and write (even though they are plain
> accesses) behave atomically, i.e. no load or store tearing or some
> other way the compiler miscompiles this. The safety of this idiom in
> this case really depends on how much we trust our compilers. Nothing
> new here,
> 
> Correct?

If "struct file_operations tty_fops" and "struct file_operations hung_up_tty_fop"
were implementing the same callbacks, "After a function pointer has become non-NULL,
it will never be NULL again, but will only ever be updated to point to some other
function." assumption is correct.

But regarding this bug report, since tty_fops implements splice_read callback but
hung_up_tty_fops does not implement splice_read callback, there is a possibility
that do_splice_read() observes in->f_op->splice_read != NULL
at "if (unlikely(!in->f_op->splice_read))" line but observes
in->f_op->splice_read == NULL at
"return in->f_op->splice_read(in, ppos, pipe, len, flags);" line.

Therefore, Greg and Linus are suggesting to implement missing callbacks so that
"After a function pointer has become non-NULL, it will never be NULL again, but
will only ever be updated to point to some other function." becomes correct.

But from KCSAN perspective, just implementing missing callbacks is not sufficient.
Linus is asking for a "don't warn" mode so that we don't need to wrap loading of
"in->f_op" using data_race() macro. I think that what Linus is asking for is
CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n. But I think that doing so will hide
other race bugs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42efccd9-c066-4acb-865d-a96dade123d9%40I-love.SAKURA.ne.jp.
