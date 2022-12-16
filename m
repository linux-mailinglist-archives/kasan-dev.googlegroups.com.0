Return-Path: <kasan-dev+bncBCAP7WGUVIKBBJPV6GOAMGQETGPXS7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id BA7D564EC89
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 15:03:18 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id h9-20020a92c269000000b00303494c4f3esf1670798ild.15
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Dec 2022 06:03:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1671199397; cv=pass;
        d=google.com; s=arc-20160816;
        b=ObIKmq8rl8Enyl9qqFflyTRGaGZND6d2xy0St788i1Bu3zeJ2js37/K/LhSkRbLuJv
         +IuiCS2PdKPrH0+sEuSPiit4ZQjgw1jyIdYzwsUcIXgH09jQeogjjCTv6paKy5yXBpuF
         yNSvZbEvvIdv206lP8HKtx+/o2145Rxgg8PN/g/sDzwmuPqrwwppb5ywiSZjL9c1g07e
         Hvd4ncMtsjRwztrUTdQPAFeCU27KF8KlhvWBoIaKTW7bwTuoSiY5yqurA/qBi1+Z+wRE
         hYgJjl9/09i2CQvhbgCKYpDOKeh+xYn0kXNCg47foU7b5AdlXTEKcRlqHBiyrceQd1oH
         gMow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=XUSjMwhoht4Qxt/zt51/kle/Fst2O+AU2RJRC3TzHCE=;
        b=Xvy/dSFSK5eDVQo/UYBYyhUpGtj+MnA1lgv04u0oHz/nf00vcq2VcnZxdbRVl3I5SD
         rYQX2qLXAlOJY0a8dUa0AordEYVc1eEi21XOdyU87DwP2AugFgIjV8d5SL48u0RjJErr
         dgTwfrkORgVW0nBRobvOvsW7FrLj4Pf3bd+hhz2kBuffd8EWcFjxfQq6KUwIrXrfhzcC
         ZoTWIxOR5WxKejoBRBP5dQxmNFoEsPNxB0dKjjlusXpfBLYK9sYHDhhzp2+Mhl4NXBmF
         QIC7n00XS6SqnWablyUrtCfBbKupCVe6E1mTHz/hsIQQh58sb9WXht17Y8pPzRecyEAH
         O2dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XUSjMwhoht4Qxt/zt51/kle/Fst2O+AU2RJRC3TzHCE=;
        b=B/ML9sywbdtz9Luv2skv4uUQeGo1MFM4Vmy3vbbSMgE37OzTZcCZnx2350yljql2Ov
         DrvON24lvO+Tgnej9eEU7DgA3RkOL/9ejr1N8WVfpD0XAaWHeiztRLiyenL/rRUMRZvp
         9cywB74F9Kt3F0kXjMHkNYb3exqrqhfHK8hIrmCLDlycBCWENWT3GXPTdC9PzsC2kKvt
         qTM5X8RFJYPaQM0BWBmyTQxwzvqC/3Bv0cqBDRhzQKLZ6NovDB6ZXSL/mfBpNHts5xdT
         jSwpNDf7L1cfglhokMhMa28hfSTvap7X0f/c2wIoNgEF3ATnSbvr8gQ9DX8H3emGNcAL
         Dygg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XUSjMwhoht4Qxt/zt51/kle/Fst2O+AU2RJRC3TzHCE=;
        b=5YOCsISe5mye7JypE8P72lK7msxnf2cgrWxYaTiZZvlLWiUsXo3cytpnCcmu/Cz/bW
         JZUK8HC42pKSiHBt8KQOQEcu83IvIuIWtbMtroVTvdiEaZKyV1+Wf5Wx77zrtkhqiYzG
         2exIsrGrI+okiQ6/GBH3Kz2+CRDpXlhpEQqYV0wzB4MxQxftNB3RD+ioFQqtF9YkNTUS
         2fvCBcPh5B56TKny+c8C769fl/C3kUsmqVQHHJaa8mYQ0QPL+N5AEjtjkaQCZFMkEWtZ
         FLS/HoPUyoiPV6q2tYV9vgCwi1wyjMOZOIsO/VxxJlnLjw5P/+yiBKSeyhbMt9s3xQOM
         fRcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plPgvF+FS4ya2f9d1/Ok95yWrGao6QEmBFpmkGdMUtAJEqDj2Nh
	bfRNAJpIZV3tr6DhEYL6LEc=
X-Google-Smtp-Source: AA0mqf69RDUwiZcv/bo6R1/KTA/HGYU65NWFkrMXYPAjTFvgvUP5cT2wLQjCIvJ1KbXd9E87aD7kvw==
X-Received: by 2002:a92:2a03:0:b0:302:c028:37a1 with SMTP id r3-20020a922a03000000b00302c02837a1mr35984930ile.182.1671199397334;
        Fri, 16 Dec 2022 06:03:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ee9:b0:305:c221:5e07 with SMTP id
 j9-20020a056e020ee900b00305c2215e07ls602406ilk.0.-pod-prod-gmail; Fri, 16 Dec
 2022 06:03:16 -0800 (PST)
X-Received: by 2002:a92:d6d1:0:b0:303:238c:fd1c with SMTP id z17-20020a92d6d1000000b00303238cfd1cmr18638170ilp.3.1671199396274;
        Fri, 16 Dec 2022 06:03:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1671199396; cv=none;
        d=google.com; s=arc-20160816;
        b=MWZaSMq5qDzpDN6e7H/rkvVsYKjFedclBmFhYnVpTIZOLV7LJP5qBDnNRY7pO+70BZ
         cJUhbivAZVtvEjgHjj5AJI+/ZHgFF18i+zAyBi5L+vFfAJsPs62v0/1c+NCVrQcUKE6L
         bvFDAvq8WCKiHdQYm8xswsA94aNGgnD6PfKaT1nrOAIX1Ml+GXWGu6UgGUzN9nE6UmY5
         vCVY+21oi24os/Euwfls6aiJWQWY7V1fE5OJaddHL5Qm6qnY8hc/V8EMotjJB3DftQjU
         H03B4d5hjgeepKRjXo1FYDVdcgAQtx7ha0Oc83wpS+k+yLDcZDWfYXlFJtw8JnMBtCBR
         SlLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=JmN6Qb5TwETYe7n7na4BfG+Mf9CO0IdnNSi7mBlEtvg=;
        b=BdXH1BZHypidQl3vYQis9evV44G9xSOrNBo8JTRgfEH1YtM8qro2Vl/ta/l/QYeGJD
         2RaV6ouFpwY70Rqew9HKUrgNjiT5olFU6Nyrs9Bm/5NTlsXzgokObDuXUrrAPFbQ8skX
         qctQ5SBbA4dP0RVtjs5b/3Dg2kAzGqkrJH/2ncNQGVb/pu6A1z6lEPIpUqYgy9R2CWsK
         kSKHGoCuj1/UvPj/lrp1Y3gUe4olIFIb1W3p8u9+4YOSILi1QrS5nqP/l2Rll5cqNz3x
         mf2wviccDa0eDOKSZKDnVsYH0Dl5vZJDW8lqWCCKjpYGROxS/O+HMScqj5bTnPTIX8S6
         GqOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id cs1-20020a05690c0ec100b003704845f699si155874ywb.0.2022.12.16.06.03.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Dec 2022 06:03:15 -0800 (PST)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav315.sakura.ne.jp (fsav315.sakura.ne.jp [153.120.85.146])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 2BGE30pY022162;
	Fri, 16 Dec 2022 23:03:00 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav315.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp);
 Fri, 16 Dec 2022 23:03:00 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp)
Received: from [192.168.1.9] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 2BGE2xnN022155
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Fri, 16 Dec 2022 23:03:00 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
Date: Fri, 16 Dec 2022 23:02:56 +0900
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
Content-Language: en-US
To: Geert Uytterhoeven <geert@linux-m68k.org>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        kasan-dev <kasan-dev@googlegroups.com>
Cc: Daniel Vetter <daniel@ffwll.ch>, Helge Deller <deller@gmx.de>,
        Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
        DRI <dri-devel@lists.freedesktop.org>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2022/12/15 18:36, Geert Uytterhoeven wrote:
> The next line is:
> 
>         scr_memsetw(save, erase, array3_size(logo_lines, new_cols, 2));
> 
> So how can this turn out to be uninitialized later below?
> 
>         scr_memcpyw(q, save, array3_size(logo_lines, new_cols, 2));
> 
> What am I missing?

Good catch. It turned out that this was a KMSAN problem (i.e. a false positive report).

On x86_64, scr_memsetw() is implemented as

        static inline void scr_memsetw(u16 *s, u16 c, unsigned int count)
        {
                memset16(s, c, count / 2);
        }

and memset16() is implemented as

        static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
        {
        	long d0, d1;
        	asm volatile("rep\n\t"
        		     "stosw"
        		     : "=&c" (d0), "=&D" (d1)
        		     : "a" (v), "1" (s), "0" (n)
        		     : "memory");
        	return s;
        }

. Plain memset() in arch/x86/include/asm/string_64.h is redirected to __msan_memset()
but memsetXX() are not redirected to __msan_memsetXX(). That is, memory initialization
via memsetXX() results in KMSAN's shadow memory being not updated.

KMSAN folks, how should we fix this problem?
Redirect assembly-implemented memset16(size) to memset(size*2) if KMSAN is enabled?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/86bdfea2-7125-2e54-c2c0-920f28ff80ce%40I-love.SAKURA.ne.jp.
