Return-Path: <kasan-dev+bncBC5OTC6XTQGRBU5YYO2QMGQEIIVZFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id DD3F1947C79
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 16:06:15 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-44cde9ed81asf127817781cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 07:06:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722866772; cv=pass;
        d=google.com; s=arc-20160816;
        b=trr+e1Menw80N6y3tHrV1jtaWRcg0h11ADvZoUm/CwVcMSP90oKmYB4ajjHzfbir9G
         s3ZKftz5B9PVtTRwslZYe9X4yiHBRuCOF/J/O3K9gji8VpMT6GskZwYwqllyG0byo64O
         IKHfatd1Fu4t8m1VBHcbR4Y3+YVDIRaTLx5w4Vyz4riNYjOVnzwCL9mzp0V7L05sd/a9
         0eAWWXtJ/nqN7xsNm0qXLcwl3ex/ADc4guyw8nAkUDcA1F3qOnUhMyGSUfhbWR3eQFaI
         OKxRyaG/ReDxvMNPQmMEy2NPrP4kgFVNuF7qpVt40V8QhUiRiPXUTPow4/f7Xj3mj0y+
         xBbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=mjpfUBoxeEMkh9kybbbt6oQZ8mrAz0+4FqxCyo4Gims=;
        fh=dWlBqtPnlRLfsaKBr4M5/SQWKllgzN+JZWgnA6krPE8=;
        b=BbSHDLqn8ogoDUMXXZfXzrEPZ/VNAaWH5EodV0maanmRRUiwTeyLIXrpTrDLwMSH1N
         jzrPYFMCNq7PJU0IDQhyHpJelczruP9uNQFxOIFgBiBbueB4HNZSYDo0CVT8Q/Ydm0E7
         lhtSi/N9YFH4gvIpX0IXLMAQBAGe4yr3eXefKUoURkhSU/rLH0UoJGdoGTqpOoC6v8Pq
         lAi6LudWw49qwdbeakbBUPp6e92A8EeRuKjcmb3c7Z0KV08a328VgYrY90J0kBUjCMWw
         vCuBVByXzIEUADdWedFh8Gc1rfrcg2aTVoWtbr9k6kqLA2X558+qK47Sns/kurMVMjki
         hoyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YFDLJqEu;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722866772; x=1723471572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mjpfUBoxeEMkh9kybbbt6oQZ8mrAz0+4FqxCyo4Gims=;
        b=auphDzmG7u6eOQMZ8sQIPwFh1UKOEvMhLj7RjyCFMVE3yCB40vpVL2/ZdxoczrIcMn
         hWUqeWNFPELMJ7TayF9ixuuT4XbHT8eSw7+88ON1TiLAmvw37yz4pft/oF/wWzHxHdqg
         ebUmmy3qb81Bx99hcRFa2AazxUSRWd6zRdQySPT/q4rtIBcnCgDFYMAyvYs6V5LS9LfA
         ywmBBz3z32iCIt4DHTXvpgCXjKKKWf1S+r8dM57MfsQPy7qF9qPKz5eyDd0RYLamwl1v
         9US/5ZuW58vwIlTcBOWg7dLpqtB//D8A6X2aXS0VNM0h2XaJlB8gymMAnLCD7zADcRQK
         a8HQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722866772; x=1723471572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mjpfUBoxeEMkh9kybbbt6oQZ8mrAz0+4FqxCyo4Gims=;
        b=jKgxCxQjz8qcobbfD8a0+ZLBuOTk3FIc3yXmoQ1omrT9SIcIgzjwpQq+lGN+vwO/YD
         57l6/870Op3mospZOhiClWPttYfuV6tYh173RxuAlINNg4iLW3/tmREGvcGP9y6fGotL
         vtsasOC56Ne88//2eYBcKJtgxq7VnK32Zsuyxl8sv3vF7DLNdIqBeWkXHbPI7ojnoQqs
         2IAMlIx52pRKdPapCoY+Ek3Dem8K+nvd6tNIw0ymFlAW2GCWCuFp9DMcsQH3MbfSjmfV
         H+ZQ/LquM8Ebzq+cKFo4L0G4RgUQTMiYqPVVp1taoH4cjouFULmsK2eVm0iqaENFkvVv
         Tsug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722866772; x=1723471572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mjpfUBoxeEMkh9kybbbt6oQZ8mrAz0+4FqxCyo4Gims=;
        b=p2+hXw/v+ipJZ0LTfA93oP6EwoKYxAHj/GraIJ6jd23zUcCd/2WpAZZw4p4mLSI03I
         IF70UuYCa/If93uNtowNy388TIlwSGapx39I0D8I4GMRwaxbInw12RwttRPtDeSGdea3
         U/TppYiV6XGRvNHrONOgOX7o1MdS5QmVwfz6BySkkwOUteRQqqX7SXpoRoxhBIdF3fEV
         6Nn2BzcdTgacf0bePq2S78b2lFnWkgrhILLLbSNLkSK0Vq9t46zJXdMASaiovpsY0vpb
         H0lbjyEIHPOOrW6yMCc2YDDJ8Ik2krW4xcaniGNN+bId0YYYe+iBVO8nYcLg2mCr6KLf
         vfiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+wEx4uKEkkbiMfWM68gfEETpNpxVpNIBlFZpvFx5vQAHOhFRx6RfstzZQxOrOq44GyYys/TfTeCiu+B7TlWzSUotBiN9i5A==
X-Gm-Message-State: AOJu0YxUxfpXewVx3Vh3qWtEmSqG5KmQ5LdmG8y2CwPpghHdrxCVKkXP
	5VtCDSAnsU4A0PNY/GNGXG2yH3lGbIbRrPV+Zlser81zNOt1RF2O
X-Google-Smtp-Source: AGHT+IHGPRCR1PjA3rQKzmzM/c8qK0xFd047RNqY4W4kaKHsmXkn+Qy49svjH7a3euqM4g26ekJheg==
X-Received: by 2002:a05:622a:11c1:b0:44f:f7c8:b157 with SMTP id d75a77b69052e-451892c0734mr134609321cf.55.1722866771704;
        Mon, 05 Aug 2024 07:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5dcc:0:b0:447:f65c:10fe with SMTP id d75a77b69052e-4519764a793ls15795221cf.2.-pod-prod-01-us;
 Mon, 05 Aug 2024 07:06:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWVzd6RWJU9/1H2EaipdIJol4kwAv3VK4TlTWViB9VrdGdGo7K3mWDfnkAq/8XXgLxjSUz/SzAm6HFvZteIAcSziDmX3NoCKzZl0w==
X-Received: by 2002:a05:620a:2a11:b0:79f:1915:5b3a with SMTP id af79cd13be357-7a34ef45320mr1649397485a.38.1722866770979;
        Mon, 05 Aug 2024 07:06:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722866770; cv=none;
        d=google.com; s=arc-20160816;
        b=MxLcSrTH3YFwQez3PXUnMrntU5ZmunMDQ+oKk0s5GjoVp4+mLfT+u/934O8mXfjQuA
         QXlhY6gyJSUyynL+qW/t+OD/SRtxF/wWUKxyNsIsd3AF3ANMcX9Lmasmpkk2V1lH8KR5
         Nvb1ZB8GXrOOjLJZe05KLzsGebD5T2tvd9FiClv1y/CIGwqSe9N6aYUTOTAUw7YWg7BH
         /t68Mw61j3vUfdZcJB4TU16VvFjU8KAo5GLTqtchuTuaqHnrF2r8dZAecir73KHcqdoD
         Wjlwh2c8NAVxy7UbBb4VT6xYOg1HhPTfOwaXnLCYcl7Zy8y0XF0koiH9/9NTEsoimuOA
         vLyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=4TiTVoaw5pa81TXpr6m/9NMpldEij9Zgtwh5o7f1ADw=;
        fh=Xx6CKQpN1TsKqRlBVPxfj9xLrBabjfqvcN00T/dzmW0=;
        b=TG4wvSFmm8EnPDjV32pYcPwgIs/ni9vSCdyPM1F3UXEejt9NXLquAo1XerJVzNzK5P
         u7YhO8F2bkaVyBLqr8gQSAMKqjmfV3p7kiIvjM6MudxHRlxwVZA5vvbv7JZSp7RTzFY+
         J742Ki/htQ9h3SrNmPRzbExn97Eb3n3jMHgRUuxNf6bI4omsYCusHNG/qmzOKJCQyvM6
         harYTXSx11/XA3VL9CqyFZia0CZjTGFh0dC7Npo3Ef3c/sKv1jE3V+8WMzWqo3Kt+5w3
         uw6VOrkOjG9acBXOyCYeimFSGN+ULlXr8jyq107PWZew++MIa7xhzS8/ciSTYo4gCpx3
         r67g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YFDLJqEu;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a34f76d203si35677185a.5.2024.08.05.07.06.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Aug 2024 07:06:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-70d2d7e692eso8196910b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2024 07:06:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWioIi1lPzsfvLLBKaKFeIrnhH676ZPYYJwPqtS1taELZxJLa1HZZkheqBfCqK+me6Za/a05JQoSnYDhSF3pjvbHua6p2P2CkI7DA==
X-Received: by 2002:a05:6a20:8414:b0:1c2:8cf4:766c with SMTP id adf61e73a8af0-1c6996242f3mr11233300637.33.1722866769847;
        Mon, 05 Aug 2024 07:06:09 -0700 (PDT)
Received: from localhost ([183.226.244.186])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7106ed2d029sm5435082b3a.199.2024.08.05.07.06.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Aug 2024 07:06:09 -0700 (PDT)
From: chenqiwu <qiwuchen55@gmail.com>
Date: Mon, 5 Aug 2024 22:06:01 +0800
To: Marco Elver <elver@google.com>
Cc: chenqiwu <qiwuchen55@gmail.com>, glider@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
Message-ID: <20240805140601.GA2811@rlk>
References: <20240803133608.2124-1-chenqiwu@xiaomi.com>
 <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk>
 <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
 <20240805033534.GA15091@rlk>
 <CANpmjNPEo=9x1FewrZYNG+YEK_XiX5gx8XNKjD9+bw7XWBV9Xw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPEo=9x1FewrZYNG+YEK_XiX5gx8XNKjD9+bw7XWBV9Xw@mail.gmail.com>
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YFDLJqEu;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::435
 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 05, 2024 at 08:50:57AM +0200, Marco Elver wrote:
> 
> The "allocated/freed" info is superfluous, as freed objects will have
> a free stack.
> 
> Consider a slightly better script vs. just using grep.
Well, I think using grep is eaiser than a script to find leaks by a
large number of alloc tracks.

> /sys/kernel/debug/kfence/objects is of secondary concern and was added
> primarily as a debugging aid for KFENCE developers. We never thought
> it could be used to look for leaks, but good you found another use for
> it. ;-)
> The priority is to keep regular error reports generated by KFENCE
> readable. Adding this "allocated/freed" info just makes the line
> longer and is not useful.
>
How about print meta->state directly to get the object state for its
alloc/free track?
-       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago) state %d:\n",
                       show_alloc ? "allocated" : "freed", track->pid,
-                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
+                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
+                      (unsigned long)interval_nsec, rem_interval_nsec / 1000,
+                      meta->state);
> I'm happy with the "(%lu.%06lus ago)" part alone.
If it's still a not good idea, I will follow your suggestion and resend
it as v2.

Thanks
Qiwu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240805140601.GA2811%40rlk.
