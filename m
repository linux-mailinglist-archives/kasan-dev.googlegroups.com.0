Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBO6WXKAQMGQESKUTM4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4012131EDD0
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 19:00:28 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id q5sf1275925wrs.20
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 10:00:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613671228; cv=pass;
        d=google.com; s=arc-20160816;
        b=h9YK8tGs0TNGau509AkUCGSdPbQhyz9V8AJd3UtlFqCwFapFIUL4rWwjmvfpz4OO7W
         +mFnWSKUFqoUG3HYWVIm3JfVNNLQusMDsQRbbf1Y1tXUts9LmuViCrVaWqJQhIqi+C33
         l+FcqWqdkl2W5kNuRDU4DtuCi0tP7yBczZ58xS+u4FVSgJ4DhORLSTtT7MpVKONsIyA2
         vrFdkzAoQF0nxISkPaAitQlXqeb1hIU5GufK4NyhsSeZHmJwRs4zj4+TTqA5m2BNyIzq
         JhAVRPcPiuw2ubEzu1loevExGZOhvsRA/4tsdzq1/fJyvV2PpEB1jamMMMD387kCrmSC
         Sxjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=DnSk9ig7/+bLtVtr70m96eurjK+Z32U5yKHYiAzIfso=;
        b=VkM16Wmj64/WFGlDtFPdWIn6CYvb2oOjgErGLuXySGhnpsWagx1xGc7sDX5qsb5TuZ
         ztGdxTKPU7on+eiKxvD7kxkDX1iIZlWGX7Pds/57VUCCDXRvmA2dhcqsah+pKoCAxZow
         ur3tBCvcSDVuCHkFdMQHgQaiQnpkCfHPfAFxTMxcOkPNPidauMpZn0dAS5wZW4Ig3SU1
         3Iy08F3mPLy/7SAccw/XlTD93DBku4X5SuJteoLFwh1Lv/xWeteLwHOjShNElQqrOyyC
         NrRTu6FIMAA6niajEQTSj2jgoH/yDGfW9paLD10wZDf6CzDRnxM18tYBKQg8KMRSXTq3
         BP2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DnSk9ig7/+bLtVtr70m96eurjK+Z32U5yKHYiAzIfso=;
        b=j0lLeEJj4BMGRFRXoqX0QR0y9Oz4gYgg0MjKX9GTtc05dINeie8KRYRwLqEwpnjooO
         c6U1w4NRG5QTVFMxEEQ6BqaM9EhLgq4ntarBAMsq0+02Kw9gL0xOuHGDlduUWKXSkve/
         0iorXnrokTs96xHmJ/Swbzfh+9wVxqsiXgPLv7+nEB32ntMZSFiMJUaxikC6oZdDpq+t
         nEldkaDyNpEoR13UAavLLy33w9fjqKCkVDgAyj6tJhFPw362er9oi73sFJSeFOmgpfp5
         0+RPz+SMPaDfrbI4CxWaBKXo/Ugrer9Qad8moFU1pQl778bJeA/KwQ14jmiU/ezuffZw
         +atw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DnSk9ig7/+bLtVtr70m96eurjK+Z32U5yKHYiAzIfso=;
        b=KR7GEsuxLnJbC7eoXUIt/LxPkcvw6qWo2WrTvAdY+pYPsmxOwF9sOK9/msdi0MsGp8
         4OoZK2ySi51ZveWP3d034Ydv8GB6dn8yL/PnEJXZkVdhlyhICe9LcULFHW8T075s/Spl
         b/VAB+fHWlg2ZKQBlcjjKPb1TMaRae404ngu7Qj3OpipDPApS0kvXiVejEEXgD4GFp52
         UA5aCxNYGqIX+yt5At2/6aMiWFEyOBD2D+koQNRHGo0xbSDrELjq53w80UTauGuBElby
         ucYy7Io2WyCac3x5b/fLkBAWtF5OzdftBdT0JjPCBn0YXLLlGJwDBBN9/5BXMp7eHqKA
         1BCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZtzRt2vuscWPG4pCk/ba/F17PjM0p7CprCZaQ6W6FZUquRZbE
	dUrgQYM/lFLPu2kVhjvO5sU=
X-Google-Smtp-Source: ABdhPJxGbkRFw53oB8XKXAjZj5epxpkhfLGEpwYD/vpfAxhL5TIsYySVJg/yRXBWDD1Q1FF8ZlsLWw==
X-Received: by 2002:a05:6000:c1:: with SMTP id q1mr5598288wrx.114.1613671228000;
        Thu, 18 Feb 2021 10:00:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1371:: with SMTP id q17ls1755089wrz.1.gmail; Thu,
 18 Feb 2021 10:00:27 -0800 (PST)
X-Received: by 2002:a05:6000:f:: with SMTP id h15mr5535872wrx.148.1613671227276;
        Thu, 18 Feb 2021 10:00:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613671227; cv=none;
        d=google.com; s=arc-20160816;
        b=Xgw/u53OyYHcNjV2M+a5JTDVUwI7P2utGd58TIRLiT4sE1Wcf4MLcbTSi1o3PGOzct
         DUeXJ5OfHJ6oMDWDGhtRZ2JbudfHZ/UEoes2M+DMpXDod8L16/2HnRglesHWcpzYgkGV
         PLmAdvNV2iu8yEYUBysNqTEjgMhmQAq0MmEfAVNBNGpN73jgNl74pMKTkwnK8fN361hH
         Cbd7Z2D3yXwa0p7d+sUcxfYcHrKV4LQF0xIouufgNnqTLKs94BI/JoWka/qHG+FWxCL1
         Ty5MfrK56LK5mauSfpHETynGrvMKyq3CYTPr3NJZDAoZOhTeFAqh3vJROHT1Dxf1JE8A
         od0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=0//wmsYqSDWPTEl3q8e7uURZZrDecsCn7Qk7A+TPQwU=;
        b=lTUb3DrucoCkRvTIdWJUZLloR2Cg8YgUS2vodhkc6OwHTl4nyxS0v61VVA87aTOpcL
         9Ab6skRdG7IQW7AcWh3W9MtKuhI0MJe53dO64T6z13TaolfKz7Lst1rdwv84OgmNpC+f
         +s8NoNAMRZa/44Znoxz/+dNqCIQhv2bkoaPH9o8dQd56wOtjIm4WMARTCsTUeR4MBC9F
         UunseYDTihRGl/LWEOjYaYNCtmPYCYn9g5my1ou+lLDsZsmytEDwAYim0BOawBjmCQWO
         jt/IT5YfYoIj5PO3iMj7v1gz2jbRjiomc8alkZQ5Gy0P8JsYTSbwnbj1+DQM8+k4kHNs
         3SXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id v6si232378wri.3.2021.02.18.10.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Feb 2021 10:00:27 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94)
	(envelope-from <johannes@sipsolutions.net>)
	id 1lCnb2-004n8X-1t; Thu, 18 Feb 2021 19:00:12 +0100
Message-ID: <e3d412224ec1ad73c8c4dbc42a17e8e481dc8982.camel@sipsolutions.net>
Subject: Re: [PATCH] kcov: Remove kcov include from sched.h and move it to
 its users.
From: Johannes Berg <johannes@sipsolutions.net>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>,  Ingo Molnar <mingo@redhat.com>, Peter Zijlstra
 <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>,  Vincent
 Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann
 <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas
 Gleixner <tglx@linutronix.de>, Ben Segall <bsegall@google.com>, Mel Gorman
 <mgorman@suse.de>, Daniel Bristot de Oliveira <bristot@redhat.com>, "David
 S. Miller" <davem@davemloft.net>, Jakub Kicinski <kuba@kernel.org>,
 netdev@vger.kernel.org
Date: Thu, 18 Feb 2021 19:00:02 +0100
In-Reply-To: <20210218173124.iy5iyqv3a4oia4vv@linutronix.de>
References: <20210218173124.iy5iyqv3a4oia4vv@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.5 (3.36.5-2.fc32)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Thu, 2021-02-18 at 18:31 +0100, Sebastian Andrzej Siewior wrote:
> The recent addition of in_serving_softirq() to kconv.h results in

You typo'ed "kconv.h" pretty consistently ;-)

But yes, that makes sense.

Acked-by: Johannes Berg <johannes@sipsolutions.net>

johannes


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e3d412224ec1ad73c8c4dbc42a17e8e481dc8982.camel%40sipsolutions.net.
