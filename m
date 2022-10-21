Return-Path: <kasan-dev+bncBAABBCVKZONAMGQEXUKIGCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 12A6F607D62
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 19:21:16 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id j8-20020a056e02154800b002fc89e9ebeesf4129160ilu.16
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 10:21:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666372875; cv=pass;
        d=google.com; s=arc-20160816;
        b=ditLl8Wq6iSNaVYqT9m6Q8nNN26LHraQIfsHB4lDoVOTShhCTxLGmVaxUnGdVwty7f
         UZBFJjliAdJuGIKwli2i+9/+bV4tT/QYF1qiVZHyBZ8qlWXOLaYIbZNh6pLLTuH9IHHV
         ZYEOrq0YBY2Q9Rg/gt+zIYT7f4Qbl8smkgeYOEg36jAJru2dpv8zBMryS7totBCQc3Qq
         w0ioeQh+lgoPHiS/PY20ptguWm01e7B9Xvs8/ccPyqZso5Bo8IlNzWPFy915WBVz9NU1
         cLipPMuvZIZUlv3efKUhYEXL9PAZSWTzKOSjmYiELNT+YI/71O2V7SZlxA4DbO+G/GZ2
         BS8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mvohJcRjTxeRSIMKeTUGOO4cygu02/adl4YHr9IND8k=;
        b=BBBP/22HE2mA0sun4M2i1B32lRVHEd3fjQQHFv2Lr5ICbJzhWNKWY0vPH2OQ6TEOZS
         i7SdLfpCTk2bLg6aEk0uy4otPGhdvDWkmk251/Oj0az/0RoBvdfkC6nLNuJGPmyS2DY8
         wC3prDmamJSN34MBt2078/+pzvBJydJtD5vrgImo71w+RlTnkT54JMBLmrRI/T+3V8wL
         vzXMrPUK2mCM+LvYR90pKd21FggH1C7PbWxi/Ml1VJns2+SNsIKzVHzHHszmzwOOnDQb
         GJjLcWoBB52jyBPPyj2KAAJoCsbLTSpSg03Rdnd+V+q4fhKkRNzR9e1kJTeldBxp5wP4
         XLgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sbc+CEwF;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:references:in-reply-to
         :user-agent:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mvohJcRjTxeRSIMKeTUGOO4cygu02/adl4YHr9IND8k=;
        b=av+sunpSG3ugapq1Oy9CwjHDptRp0GQpX4GhHRWnldb0ntRPwXhz9jFF2QzbvwTuUe
         br+dYvqlDmxIyYiorxZuOggVDKC87NBerCHLxKXWKYH0pE2L6ZFiTrkmuhjwzNW+5F8f
         j9PVPS1P4GcKp676lakMr8NxY5ndj//W7QkDzzFKtH9BtH92mUQhLyMC6X5BeinIR3b1
         MV7xzeridHJGIWquLyNxNpfQIlOODUiPmJ4I9mcKu+Q6jidd7xAgmI/9u/9DYGZgZbb8
         nc4y7K9oiNvsQQELEEFFJiULBPxw4g6FX8UbNgA4ovp3olM9uKI5yRVfY3pSvjNrL0GR
         VBKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mvohJcRjTxeRSIMKeTUGOO4cygu02/adl4YHr9IND8k=;
        b=jQU1zlamQ6EcqhwRgoxhcpdyX2mk8GP4R0gXi2whRG27QbeF271CzRZK0b3Jo7wA7L
         9jk79IJC+kNjESr0idhWPtrifecshscc7pPxpNl43A45HiA8Lg5by8bhE3KNyOmiMJei
         1/ASQLM4MKPq/krX4o95HbKs5rAMIKWVYKeypPLfUhd6FbJG+F2xCEZp3L6ptlIcNSBx
         G8NGw4d4TjSnw/CDJvzQD+y4pCoZJ1fMH1hdaPSFeIDM7LLpNOvUloklJi5ozqVN5CV0
         iuML7MZ3P7ccb/vv0fjt2U3zD7GuBsA2oRSf9X7XeLzHDIEPxPECDgl+ms0MVugvyJ1Z
         kmWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Ih3gz9+rOQcdczxAUg8oDMmpdnIQ5MYybbN8TBni3uJsfVmkX
	76dH41f2T8WgvZqNEFMxr5o=
X-Google-Smtp-Source: AMsMyM7LMlybx0LoqjKiXH/1xsXs2VQMI2VMuErQkD/uRbS3sxddTuI9bx28qZd2ZkLXtNySDZaODw==
X-Received: by 2002:a92:d686:0:b0:2fa:6226:6247 with SMTP id p6-20020a92d686000000b002fa62266247mr15013822iln.79.1666372874741;
        Fri, 21 Oct 2022 10:21:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:bcc1:0:b0:685:acbd:cc57 with SMTP id m184-20020a6bbcc1000000b00685acbdcc57ls482263iof.3.-pod-prod-gmail;
 Fri, 21 Oct 2022 10:21:14 -0700 (PDT)
X-Received: by 2002:a6b:e707:0:b0:6bc:8875:4229 with SMTP id b7-20020a6be707000000b006bc88754229mr14348501ioh.37.1666372874036;
        Fri, 21 Oct 2022 10:21:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666372874; cv=none;
        d=google.com; s=arc-20160816;
        b=rPdtnVw3nRIsTCnhV1TO81TcovWB9heUAsx7ODfWZcZTUsuE63E65kPhg5D6b1X8eb
         +IaA+imZ25eSwZNMy4cplHuKkECDmPkW0GzNd0/p4PbSroA8+xpBjXewj04C4twbbAtQ
         d2GLywuPzG2bGWJG+CVhmqwDjrdDENRL34VDjp4KbhYxIXsEghkjek7zjGdcHHiSowXi
         ea6hPcvJBhQit52oBAceIUN8GgeYv1826CojFZAWdjcoW9GtaMG6XscMDIV0p21olBfr
         P9IRbLwQz5JxBqoCMYYTtHperblzh65IlSDXlhKd6nyPaXIdbDc8ONHxE9pQNPPUlXaz
         TNkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=OdWOQBaqPtwH7WTxoM2zqstOKsGwBaRxBfceti0LzbU=;
        b=jsk0MbXbGp9LbIox58ICk8glkz1882udKFCJp1TunDu4cwyji+Va1kEK/FrPifBONu
         XTJuebPW8/v9m78haywh4BrOxUa7VkrK0w89hTAE4hnHIwFXiv9iWLPsfcY6nXNcUnTy
         AfFn57oR/YvhDoMN5AIT7Se3/Klkul8mojZgc40iRvfFaxk+0Wi2rTbirwGfA05QLMpH
         edCWDPmtWowMsUnYxky2HfLLtc5kZT26dJHPwYTqlTGuPWo8tIgGNptvj0HrVvcRiRnD
         /AQ4RuLnNl3yF9wgRGhhJcyenk28GXxah0d9hKGfTjf2axmw+ONTkqK2GkoZyaKg/kyk
         CYpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sbc+CEwF;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z3-20020a92cec3000000b002ffa34a9cf8si48664ilq.3.2022.10.21.10.21.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Oct 2022 10:21:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A122F61F1E;
	Fri, 21 Oct 2022 17:21:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 031EDC433D6;
	Fri, 21 Oct 2022 17:21:13 +0000 (UTC)
Date: Fri, 21 Oct 2022 10:21:12 -0700
From: Kees Cook <kees@kernel.org>
To: Alexander Potapenko <glider@google.com>, youling 257 <youling257@gmail.com>
CC: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Alexei Starovoitov <ast@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>,
 Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>,
 Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>,
 Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>,
 Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>,
 Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>,
 Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Petr Mladek <pmladek@suse.com>, Stephen Rothwell <sfr@canb.auug.org.au>,
 Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>,
 Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
User-Agent: K-9 Mail for Android
In-Reply-To: <CAG_fn=VE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7AHr-A@mail.gmail.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com> <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com> <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com> <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com> <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com> <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com> <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com> <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com> <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com> <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com> <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com> <CAG_fn=VE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7AHr-A@mail.gmail.com>
Message-ID: <EC4E1360-080B-4754-9A95-79B7246C5605@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sbc+CEwF;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On October 21, 2022 10:02:05 AM PDT, Alexander Potapenko <glider@google.com> wrote:
>On Fri, Oct 21, 2022 at 8:19 AM youling 257 <youling257@gmail.com> wrote:
>
>> CONFIG_DEBUG_INFO=y
>> CONFIG_AS_HAS_NON_CONST_LEB128=y
>> # CONFIG_DEBUG_INFO_NONE is not set
>> CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
>> # CONFIG_DEBUG_INFO_DWARF4 is not set
>> # CONFIG_DEBUG_INFO_DWARF5 is not set
>> # CONFIG_DEBUG_INFO_REDUCED is not set
>> # CONFIG_DEBUG_INFO_COMPRESSED is not set
>> # CONFIG_DEBUG_INFO_SPLIT is not set
>> # CONFIG_DEBUG_INFO_BTF is not set
>> # CONFIG_GDB_SCRIPTS is not set
>>
>> perf top still no function name.
>>
>Will it help if you disable CONFIG_RANDOMIZE_BASE?
>(if it doesn't show the symbols, at least we'll be able to figure out the
>offending function by running nm)

Is KALLSYMS needed?

>
>
>>
>> 12.90%  [kernel]              [k] 0xffffffff833dfa64
>>      3.78%  [kernel]              [k] 0xffffffff8285b439
>>      3.61%  [kernel]              [k] 0xffffffff83370254
>>      2.32%  [kernel]              [k] 0xffffffff8337025b
>>      1.88%  bluetooth.default.so  [.] 0x000000000000d09d
>>
>> 2022-10-21 15:37 GMT+08:00, Marco Elver <elver@google.com>:
>> > On Thu, 20 Oct 2022 at 23:39, youling 257 <youling257@gmail.com> wrote:
>> >>
>> >> PerfTop:    8253 irqs/sec  kernel:75.3%  exact: 100.0% lost: 0/0 drop:
>> >> 0/17899 [4000Hz cycles],  (all, 8 CPUs)
>> >>
>> ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
>> >>
>> >>     14.87%  [kernel]              [k] 0xffffffff941d1f37
>> >>      6.71%  [kernel]              [k] 0xffffffff942016cf
>> >>
>> >> what is 0xffffffff941d1f37?
>> >
>> > You need to build with debug symbols:
>> > CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
>> >
>> > Then it'll show function names.
>> >
>> >> 2022-10-21 14:16 GMT+08:00, Marco Elver <elver@google.com>:
>> >> > On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com>
>> wrote:
>> >> >>
>> >> >> How to use perf tool?
>> >> >
>> >> > The simplest would be to try just "perf top" - and see which kernel
>> >> > functions consume most CPU cycles. I would suggest you compare both
>> >> > kernels, and see if you can spot a function which uses more cycles% in
>> >> > the problematic kernel.
>> >> >
>> >
>>
>
>


-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/EC4E1360-080B-4754-9A95-79B7246C5605%40kernel.org.
