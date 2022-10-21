Return-Path: <kasan-dev+bncBD6ZP2WSRIFRBAHRZKNAMGQEOD3AGBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B062607A5A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 17:19:29 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id c130-20020a1c3588000000b003b56be513e1sf1579555wma.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 08:19:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666365568; cv=pass;
        d=google.com; s=arc-20160816;
        b=dFwkCzP1aAGOssizeSehr/ym/m7ifnAl06Tny/XJ29gN3Rr0jStrnOsvq7mcpf796d
         rx6ZcJhN3qFcPKujqSX81aEZSvUkJYYZ3JjHWSDs3k9LmqGpfQadt06IC7ozTYcfQbXC
         iFieBS7WPuzzZaueeBIhJf4oS2Pry5blReaTPeD0pF5jp26Ku7Rvb/fJTbshLp0CECa3
         7ieGl7zyGV8IpBuRaTSdFgJjBr6/vziTvGHnhTpgHN65UpGcpoGldS8ed7fUt8pJ5Q4D
         hlzd+FVrkhq3puFhp3uKEkqwX12Ff7zHnnH4iQIEt5YWKqUZRgQz4e1eJaDxFFTapHfD
         lOEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4UEfLGAfCbJoxQYkO2sb47G0mLLtZ4pWUxJxKCfFQiI=;
        b=Bz3D9bLbWIFforR/cCd940GeQl2Fkuz37CzetS7VjgbIPfjTZ2FmZ+TMME7W8Ot+2c
         H9xGCeHvBfPIw5mJjGM6X7x9CYZSGi112ptbx6T0gVVwRbyrmPreXhNdszpp7pJdJkgr
         OG4pV2lUy9JpivC6fFFAL5MzICVmjDRIMpJrxhlt4QGS7SsOygsp8eNw68Q04VLp6/fs
         z4yGWdc3Ha39+nEYtmLu8o+kjD5ZxPte9sHi1xEvGfU5Xt8aFIrRZy/s1DdO4mVZBfBE
         UBpwDBUcWVHGgaXvfaCzkZpHHqvNg2EFJ6hPrWuSox5FINHT2Gc42daQF0AXihxCN26w
         rNwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XhEIMtoh;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4UEfLGAfCbJoxQYkO2sb47G0mLLtZ4pWUxJxKCfFQiI=;
        b=QWcVyAZopXDadYU4S+Zt5/4zT3kvdLSTO9tpVSygZyTrnG29wGJQyCxyj9Fb2uvwaU
         EZkDhrxPrUG9jimCueGENTA2RzVXmYQYTJ5B8q/oeXfTcu6+vPos0QysnkH87AWz50+d
         rEPnRgrF1eAhOQiOGDtvEyJ41kOQNBlzS1pj5OMxLnMqZNQpmry+E8ZzJqblEMmB/XDC
         OMMsLs1pgDkT7HpIpaH0/LQ3fnQgOmo2PpUlyw8kIPLJlWxqX8D+kJRaNrFVDdVV7ekZ
         lscI0+lSGu2bobu6Mb2PKfrgqK6C4mlFkKRdrRFri5FLUtRJCv+zz5gE4taAf03PfGkh
         Njtg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:references
         :in-reply-to:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4UEfLGAfCbJoxQYkO2sb47G0mLLtZ4pWUxJxKCfFQiI=;
        b=ByrM0+FJajm7TNeTD6lvcG9uSwQH8gSmq2oqVkQfJ6vLWKF2GdrJMX3lTTyAWm7r3i
         njxtEFNQjgvH/S1huWQPMdheU1pqbAS1pag99ruW6A2skMPITn1Pf1GGlVq2f391Iuha
         funOViuFJ7PziJKn3F0gpdGgCiPR9Rzo5Vy7pmoqExCRB6HWi8Dh9P/0VV63G0B3yQrU
         B+E2s1m3HMONBsyGF14kz+mADc87EBXMrunsmAFpWuO5r0vzNcyoJqrCmCkRrMbhTjoR
         ukfd0LMBIpHwdXe/EU4P8fBPtMYbqrNogWBGVPsXUNABStG8Md9EQOz/4tgpu8e2rrTx
         +g+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4UEfLGAfCbJoxQYkO2sb47G0mLLtZ4pWUxJxKCfFQiI=;
        b=cebTSaFh3xTBhWu6jeKnPWyZUIE2aFFQkKZUWMK+jjT2P62WGaNjcrYCMsIht6XCSt
         n5UK7Gg0OVClfBokVunOdSVzNT/dti36gAryVKWkZxCe86I3EwLJkhpYv35nUGn5Y84R
         MkZ1GI5na7PkwTcAylqzSF/g89A7u4lsmASIE92Tv/vupcM369DaQoUcLix7s47ZcpNt
         92zTnatVrJUYFo+fOou7EspYYqIpvYyFRTnSJ5OlX8B/boHSqScGvRotLBIRC3QEwR62
         7ZyjSAyBUhhL5nGMgQy0uc07hLsJptUoJRFG5gyfrwkz1PyTIDQ/OAfQi9X4lfIa1vnL
         hPPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0yDy7V1dn/YBgNAjvnqYohXd8qNn0i9OW4kaWMYqll7yuQpZRI
	xdSoB8lC48hm7w6rKRDtsrQ=
X-Google-Smtp-Source: AMsMyM4Wk6ob1/zTRZb8uQZLUU7f+E3o8q6/U6VAxkFaQjmo/6Bmg1TpK3XSHUmy4fa1BpKhYwAzqg==
X-Received: by 2002:a05:6000:1845:b0:22f:bfca:6439 with SMTP id c5-20020a056000184500b0022fbfca6439mr12793690wri.298.1666365568521;
        Fri, 21 Oct 2022 08:19:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:b57:b0:3c5:f6bb:ee12 with SMTP id
 k23-20020a05600c0b5700b003c5f6bbee12ls1384438wmr.3.-pod-control-gmail; Fri,
 21 Oct 2022 08:19:27 -0700 (PDT)
X-Received: by 2002:a05:600c:4f46:b0:3b4:fed8:331e with SMTP id m6-20020a05600c4f4600b003b4fed8331emr34991465wmq.198.1666365567347;
        Fri, 21 Oct 2022 08:19:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666365567; cv=none;
        d=google.com; s=arc-20160816;
        b=sOqLnOiXLGYmPMwLmTBmZJOqM0oEpTw/1LYM5jtj7pfcaDCZJ6wqcIlQ7vQj8iljI+
         2yETnvEx630dpnK7DxZpS5a27E6Gu4sH9RY0aO1nldL1iupmX3c5mpow2RnbT6Djh0iU
         35PzozLpmhY6RZGbpkeaKl30UYURoC4/2Mo1iBITv1bTtrTOm57Og3qlG1TBMbt5OK5l
         BDKtSsDG4yQlv+2qka6Ft5/w3UFZur9JleDo2IWGSS0CCtf8c8mKTBQ78hq0GuMxwdAN
         vhy9uXS++jestgr+oAlxMIp9Kp5akfs/jDPH4jBOafAzeopCXaOg6Ovrf8x0JRYCTEM1
         oSSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:references:in-reply-to
         :mime-version:dkim-signature;
        bh=nLPDviM40EFa/Qu4CMFk6R9DVn/gn4Pe+x/zBYpv/KU=;
        b=lwo5GAPoptdCr3IwTCeDjBGBruuHCRF1iahcUEXehyRqcElfytomnEZW5k5h24gONb
         ZVb8djUaN1jQykJ5x+bBMk98kDA/8uxkcdTkZ5jfpnqsLm0bylBzayBuE+cqujKpgyyb
         BoaQwoPb9hA+JrRMucCBm0G+YpKy1cqwmJuLnCOr2IZ/93qO5mE0sPbqZV0Gp5Uw3KTM
         NUdpDEz7/ABKvIpGl7xQPxEUJ/QVP6sr1JgbLFdbl2fN0pJgY8VrZoMGI3MSlL2/wQl7
         MmjBNPSaYWg5BluZ3EV1k3sK/Jlp/BbRxToHLwgDBZvApKx+XO23Kn1QK0jXJugyMvmi
         e0wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XhEIMtoh;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id a1-20020a05600c348100b003c6c0197f3dsi249885wmq.2.2022.10.21.08.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Oct 2022 08:19:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id o12so5663426lfq.9
        for <kasan-dev@googlegroups.com>; Fri, 21 Oct 2022 08:19:27 -0700 (PDT)
X-Received: by 2002:a05:6512:4002:b0:4a2:6243:8384 with SMTP id
 br2-20020a056512400200b004a262438384mr6716302lfb.29.1666365566622; Fri, 21
 Oct 2022 08:19:26 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Fri, 21 Oct 2022
 08:19:25 -0700 (PDT)
In-Reply-To: <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
 <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
 <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com> <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Fri, 21 Oct 2022 23:19:25 +0800
Message-ID: <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XhEIMtoh;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

CONFIG_DEBUG_INFO=y
CONFIG_AS_HAS_NON_CONST_LEB128=y
# CONFIG_DEBUG_INFO_NONE is not set
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
# CONFIG_DEBUG_INFO_DWARF4 is not set
# CONFIG_DEBUG_INFO_DWARF5 is not set
# CONFIG_DEBUG_INFO_REDUCED is not set
# CONFIG_DEBUG_INFO_COMPRESSED is not set
# CONFIG_DEBUG_INFO_SPLIT is not set
# CONFIG_DEBUG_INFO_BTF is not set
# CONFIG_GDB_SCRIPTS is not set

perf top still no function name.

12.90%  [kernel]              [k] 0xffffffff833dfa64
     3.78%  [kernel]              [k] 0xffffffff8285b439
     3.61%  [kernel]              [k] 0xffffffff83370254
     2.32%  [kernel]              [k] 0xffffffff8337025b
     1.88%  bluetooth.default.so  [.] 0x000000000000d09d

2022-10-21 15:37 GMT+08:00, Marco Elver <elver@google.com>:
> On Thu, 20 Oct 2022 at 23:39, youling 257 <youling257@gmail.com> wrote:
>>
>> PerfTop:    8253 irqs/sec  kernel:75.3%  exact: 100.0% lost: 0/0 drop:
>> 0/17899 [4000Hz cycles],  (all, 8 CPUs)
>> ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
>>
>>     14.87%  [kernel]              [k] 0xffffffff941d1f37
>>      6.71%  [kernel]              [k] 0xffffffff942016cf
>>
>> what is 0xffffffff941d1f37?
>
> You need to build with debug symbols:
> CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
>
> Then it'll show function names.
>
>> 2022-10-21 14:16 GMT+08:00, Marco Elver <elver@google.com>:
>> > On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com> wrote:
>> >>
>> >> How to use perf tool?
>> >
>> > The simplest would be to try just "perf top" - and see which kernel
>> > functions consume most CPU cycles. I would suggest you compare both
>> > kernels, and see if you can spot a function which uses more cycles% in
>> > the problematic kernel.
>> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg%40mail.gmail.com.
